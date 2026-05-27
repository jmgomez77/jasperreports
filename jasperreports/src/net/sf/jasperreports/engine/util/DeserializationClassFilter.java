/*
 * JasperReports - Free Java Reporting Library.
 * Copyright (C) 2001 - 2023 Cloud Software Group, Inc. All rights reserved.
 * http://www.jaspersoft.com
 *
 * Unless you have purchased a commercial license agreement from Jaspersoft,
 * the following license terms apply:
 *
 * This program is part of JasperReports.
 *
 * JasperReports is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JasperReports is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JasperReports. If not, see <http://www.gnu.org/licenses/>.
 */
package net.sf.jasperreports.engine.util;

import java.io.InvalidClassException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import net.sf.jasperreports.engine.JRPropertiesUtil;
import net.sf.jasperreports.engine.JasperReportsContext;

/**
 * Deserialisation class filter that guards all {@link java.io.ObjectInputStream}
 * instantiations in JasperReports against untrusted gadget-chain payloads
 * (CVE-2026-6009 / CVE-2025-10492).
 *
 * <p>The filter is <strong>enabled by default</strong>.  When enabled, every
 * class name resolved during deserialisation is checked against a built-in
 * whitelist of safe prefixes.  User-defined additional prefixes can be supplied
 * via the property {@value #PROPERTY_WHITELIST_PREFIXES}.</p>
 *
 * <h3>Configuration properties</h3>
 * <dl>
 *   <dt>{@value #PROPERTY_FILTER_ENABLED}</dt>
 *   <dd>Set to {@code false} to disable the filter entirely (not recommended).
 *       Default: {@code true}.</dd>
 *   <dt>{@value #PROPERTY_WHITELIST_PREFIXES}</dt>
 *   <dd>Comma- or newline-separated list of fully-qualified class-name prefixes
 *       that are additionally allowed beyond the built-in set.  Example:
 *       {@code com.example.reports.,org.acme.}.</dd>
 * </dl>
 *
 * @author JasperReports CVE-2026-6009 patch
 */
public final class DeserializationClassFilter
{
	private static final Log log = LogFactory.getLog(DeserializationClassFilter.class);

	/**
	 * Property that enables or disables the deserialisation class filter.
	 * Default value: {@code true}.
	 */
	public static final String PROPERTY_FILTER_ENABLED =
			JRPropertiesUtil.PROPERTY_PREFIX + "deserialization.class.filter.enabled";

	/**
	 * Property containing a comma- or newline-separated list of additional
	 * class-name prefixes that are permitted during deserialisation.
	 */
	public static final String PROPERTY_WHITELIST_PREFIXES =
			JRPropertiesUtil.PROPERTY_PREFIX + "deserialization.class.filter.whitelist.prefixes";

	/**
	 * Built-in class-name prefixes that are always allowed.
	 *
	 * <p>The list covers JasperReports domain objects, the Java standard library,
	 * and third-party libraries that may appear in serialised {@code .jasper}
	 * files (JFreeChart, Sun font internals, etc.).  Array type descriptors
	 * start with {@code [}, so that prefix admits all array types.</p>
	 */
	private static final String[] BUILT_IN_PREFIXES = {
		"net.sf.jasperreports.",   // all JR classes
		"java.",                   // java.lang, java.util, java.awt, java.sql, …
		"javax.",                  // javax.swing, javax.xml, …
		"sun.font.",               // font internals resolved by ContextClassLoaderObjectInputStream
		"org.jfree.",              // JFreeChart – charts in .jasper files
		"[",                       // array type descriptors: [B, [I, [[Ljava.lang.String; …
	};

	/**
	 * Installs a JVM-global {@code ObjectInputFilter} (JEP 290 / Java 9+) so
	 * that <em>every</em> {@link java.io.ObjectInputStream} in the JVM —
	 * including raw instances created inside JRXML parameter expressions or
	 * Groovy scriptlets — is subject to the same class-name whitelist as
	 * {@link ContextClassLoaderObjectInputStream}.
	 *
	 * <p>The method is invoked once from a {@code static} initialiser and
	 * uses reflection to remain source-compatible with Java 8.  On Java 8
	 * runtimes that pre-date JEP 290 the call is a no-op and the per-stream
	 * filter in {@link ContextClassLoaderObjectInputStream} remains the only
	 * defence.</p>
	 *
	 * <p>If another component has already installed a global filter the call
	 * is skipped and a warning is logged; the per-stream filter still
	 * applies to all JasperReports-managed streams.</p>
	 */
	static void installGlobalFilter()
	{
		try
		{
			Class<?> configClass = Class.forName("java.io.ObjectInputFilter$Config");
			Method getFilter   = configClass.getMethod("getSerialFilter");
			Method setFilter   = configClass.getMethod("setSerialFilter",
					Class.forName("java.io.ObjectInputFilter"));

			if (getFilter.invoke(null) != null)
			{
				log.warn("A JVM-global ObjectInputFilter is already installed; "
						+ "JasperReports global deserialization filter will NOT be added. "
						+ "Ensure the existing filter covers CVE-2026-6009 gadget-chain classes.");
				return;
			}

			Class<?> filterInfoClass = Class.forName("java.io.ObjectInputFilter$FilterInfo");
			Method   serialClass     = filterInfoClass.getMethod("serialClass");

			Class<?>   statusClass = Class.forName("java.io.ObjectInputFilter$Status");
			final Object ALLOWED   = Enum.valueOf((Class<Enum>) statusClass, "ALLOWED");
			final Object REJECTED  = Enum.valueOf((Class<Enum>) statusClass, "REJECTED");
			final Object UNDECIDED = Enum.valueOf((Class<Enum>) statusClass, "UNDECIDED");

			InvocationHandler handler = (proxy, method, args) ->
			{
				if (!"checkInput".equals(method.getName()) || args == null || args.length != 1)
				{
					return null;
				}
				Class<?> clazz = (Class<?>) serialClass.invoke(args[0]);
				if (clazz == null)
				{
					// Invoked for stream-level checks (depth, refs, bytes, arrays) — not a class check.
					return UNDECIDED;
				}
				String name = clazz.getName();
				for (String prefix : BUILT_IN_PREFIXES)
				{
					if (name.startsWith(prefix))
					{
						return ALLOWED;
					}
				}
				// Check user-configured prefixes via the default context (lazy, cached by JRPropertiesUtil).
				try
				{
					JRPropertiesUtil props = JRPropertiesUtil.getInstance(
							net.sf.jasperreports.engine.DefaultJasperReportsContext.getInstance());
					if (!props.getBooleanProperty(PROPERTY_FILTER_ENABLED, true))
					{
						return UNDECIDED;
					}
					String userPrefixes = props.getProperty(PROPERTY_WHITELIST_PREFIXES);
					if (userPrefixes != null && !userPrefixes.isEmpty())
					{
						for (String raw : userPrefixes.split("[,\r\n]+"))
						{
							String prefix = raw.trim();
							if (!prefix.isEmpty() && name.startsWith(prefix))
							{
								return ALLOWED;
							}
						}
					}
				}
				catch (Exception ignored)
				{
					// Context not yet ready — fall through to REJECTED for safety.
				}
				if (log.isWarnEnabled())
				{
					log.warn("JVM global filter: blocking deserialization of '" + name
							+ "' (CVE-2026-6009). Add its prefix to '"
							+ PROPERTY_WHITELIST_PREFIXES + "' if it is trusted.");
				}
				return REJECTED;
			};

			Object filter = Proxy.newProxyInstance(
					DeserializationClassFilter.class.getClassLoader(),
					new Class<?>[] { Class.forName("java.io.ObjectInputFilter") },
					handler);

			setFilter.invoke(null, filter);
			log.info("JasperReports JVM-global deserialization filter installed (CVE-2026-6009).");
		}
		catch (ClassNotFoundException e)
		{
			// Java 8 without JEP 290 — global filter unavailable; per-stream filter still active.
			log.debug("java.io.ObjectInputFilter not available; JVM-global filter not installed.");
		}
		catch (Exception e)
		{
			log.warn("Failed to install JVM-global ObjectInputStream filter: " + e.getMessage());
		}
	}

	// Install the global filter when this class is first loaded (i.e. when
	// ContextClassLoaderObjectInputStream or VirtualizationObjectInputStream
	// is first instantiated by JasperReports).
	static
	{
		installGlobalFilter();
	}

	private DeserializationClassFilter()
	{
	}

	/**
	 * Checks whether the given class name is permitted for deserialisation
	 * under the supplied context's configuration.
	 *
	 * <p>This method is a no-op when the filter is disabled or when
	 * {@code context} is {@code null}.  Otherwise it throws
	 * {@link InvalidClassException} for any class name that does not match
	 * the built-in whitelist or the user-defined
	 * {@value #PROPERTY_WHITELIST_PREFIXES} property.</p>
	 *
	 * @param context the current {@link JasperReportsContext}; may be
	 *                {@code null}, in which case the check is skipped
	 * @param className the binary class name about to be deserialised
	 * @throws InvalidClassException if the class is not on the whitelist
	 */
	public static void checkClassName(JasperReportsContext context, String className)
			throws InvalidClassException
	{
		if (context == null)
		{
			return;
		}

		JRPropertiesUtil props = JRPropertiesUtil.getInstance(context);
		boolean enabled = props.getBooleanProperty(PROPERTY_FILTER_ENABLED, true);
		if (!enabled)
		{
			return;
		}

		if (isAllowed(className, props))
		{
			return;
		}

		String message = "Deserialisation of class '" + className + "' is blocked by the "
				+ "JasperReports deserialisation class filter (CVE-2026-6009). "
				+ "If this class is trusted, add its package prefix to the property '"
				+ PROPERTY_WHITELIST_PREFIXES + "', or set '"
				+ PROPERTY_FILTER_ENABLED + "=false' to disable the filter entirely.";

		if (log.isWarnEnabled())
		{
			log.warn(message);
		}

		throw new InvalidClassException(message);
	}

	private static boolean isAllowed(String className, JRPropertiesUtil props)
	{
		for (String prefix : BUILT_IN_PREFIXES)
		{
			if (className.startsWith(prefix))
			{
				return true;
			}
		}

		String userPrefixes = props.getProperty(PROPERTY_WHITELIST_PREFIXES);
		if (userPrefixes != null && !userPrefixes.isEmpty())
		{
			for (String raw : userPrefixes.split("[,\r\n]+"))
			{
				String prefix = raw.trim();
				if (!prefix.isEmpty() && className.startsWith(prefix))
				{
					return true;
				}
			}
		}

		return false;
	}
}
