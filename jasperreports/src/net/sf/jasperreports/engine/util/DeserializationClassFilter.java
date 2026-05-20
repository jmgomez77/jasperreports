/*
 * Copyright (C) 2026 Irisel Consulting SL. All rights reserved.
 *
 * This file is part of JasperReports.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import net.sf.jasperreports.annotations.properties.Property;
import net.sf.jasperreports.annotations.properties.PropertyScope;
import net.sf.jasperreports.engine.JRPropertiesUtil;
import net.sf.jasperreports.engine.JRPropertiesUtil.PropertySuffix;
import net.sf.jasperreports.engine.JRRuntimeException;
import net.sf.jasperreports.engine.JasperReportsContext;
import net.sf.jasperreports.functions.FunctionsBundle;
import net.sf.jasperreports.functions.FunctionsUtil;
import net.sf.jasperreports.properties.PropertyConstants;

/**
 * Deserialization class filter that restricts which classes can be deserialized.
 * This is the primary defense against Java deserialization attacks (CVE-2026-6009).
 */
public class DeserializationClassFilter implements ClassLoaderFilter
{
	@Property(
			category = PropertyConstants.CATEGORY_OTHER,
			defaultValue = "true",
			scopes = {PropertyScope.CONTEXT},
			sinceVersion = PropertyConstants.VERSION_6_21_5,
			valueType = Boolean.class
			)
	public static final String PROPERTY_CLASS_FILTER_ENABLED = 
			JRPropertiesUtil.PROPERTY_PREFIX + "deserialization.class.filter.enabled";
	
	@Property(
			category = PropertyConstants.CATEGORY_OTHER,
			scopes = {PropertyScope.CONTEXT},
			sinceVersion = PropertyConstants.VERSION_6_21_5,
			name = "net.sf.jasperreports.deserialization.class.whitelist.{arbitrary_name}"
			)
	public static final String PROPERTY_PREFIX_CLASS_WHITELIST = 
			JRPropertiesUtil.PROPERTY_PREFIX + "deserialization.class.whitelist.";
	
	public static final String EXCEPTION_MESSAGE_KEY_CLASS_NOT_VISIBLE = "deserialization.class.not.visible";

	private boolean filterEnabled;
	private List<DeserializationClassWhitelist> whitelists;
	
	private Map<String, Boolean> visibilityCache = new ConcurrentHashMap<>();

	public DeserializationClassFilter(JasperReportsContext jasperReportsContext)
	{
		JRPropertiesUtil properties = JRPropertiesUtil.getInstance(jasperReportsContext);
		filterEnabled = properties.getBooleanProperty(PROPERTY_CLASS_FILTER_ENABLED);
		if (filterEnabled)
		{
			whitelists = new ArrayList<>();
			
			StandardDeserializationClassWhitelist whitelist = new StandardDeserializationClassWhitelist();
			addHardcodedWhitelist(whitelist);
			loadPropertiesWhitelist(properties, whitelist);
			loadFunctionsWhitelist(jasperReportsContext, whitelist);
			whitelists.add(whitelist);
			
			List<DeserializationClassWhitelist> extensionWhitelists = jasperReportsContext.getExtensions(
					DeserializationClassWhitelist.class);
			whitelists.addAll(extensionWhitelists);
		}
	}

	private static void addHardcodedWhitelist(StandardDeserializationClassWhitelist whitelist)
	{
		whitelist.addClass("B");
		whitelist.addClass("D");
		whitelist.addClass("F");
		whitelist.addClass("I");
		whitelist.addClass("J");
		whitelist.addClass("S");
		whitelist.addClass("Z");
		whitelist.addClass("java.lang.Boolean");
		whitelist.addClass("java.lang.Byte");
		whitelist.addClass("java.lang.Character");
		whitelist.addClass("java.lang.Double");
		whitelist.addClass("java.lang.Enum");
		whitelist.addClass("java.lang.Float");
		whitelist.addClass("java.lang.Integer");
		whitelist.addClass("java.lang.Long");
		whitelist.addClass("java.lang.Number");
		whitelist.addClass("java.lang.Object");
		whitelist.addClass("java.lang.Short");
		whitelist.addClass("java.lang.String");
	}

	private static void loadPropertiesWhitelist(JRPropertiesUtil propertiesUtil, 
			StandardDeserializationClassWhitelist whitelist)
	{
		List<PropertySuffix> properties = propertiesUtil.getProperties(PROPERTY_PREFIX_CLASS_WHITELIST);
		for (PropertySuffix propertySuffix : properties)
		{
			String whitelistString = propertySuffix.getValue();
			whitelist.addWhitelist(whitelistString);
		}
	}

	private static void loadFunctionsWhitelist(JasperReportsContext jasperReportsContext, 
			StandardDeserializationClassWhitelist whitelist)
	{
		FunctionsUtil functionsUtil = FunctionsUtil.getInstance(jasperReportsContext);
		List<FunctionsBundle> functionBundles = functionsUtil.getAllFunctionBundles();
		for (FunctionsBundle functionsBundle : functionBundles)
		{
			List<Class<?>> functionClasses = functionsBundle.getFunctionClasses();
			for (Class<?> functionClass : functionClasses)
			{
				whitelist.addClass(functionClass.getName());
			}
		}
	}

	public boolean isFilteringEnabled()
	{
		return filterEnabled;
	}

	@Override
	public void checkClassVisibility(String className) throws JRRuntimeException
	{
		boolean visible = isClassVisible(className);
		if (!visible)
		{
			throw new JRRuntimeException(EXCEPTION_MESSAGE_KEY_CLASS_NOT_VISIBLE, new Object[] {className});
		}
	}

	public boolean isClassVisible(String className)
	{
		Boolean visible = visibilityCache.get(className);
		if (visible == null)
		{
			visible = visible(className);
			visibilityCache.put(className, visible);
		}
		return visible;
	}

	protected boolean visible(String className)
	{
		boolean visible;
		if (filterEnabled)
		{
			visible = false;
			for (DeserializationClassWhitelist whitelist : whitelists)
			{
				if (whitelist.includesClass(className))
				{
					visible = true;
					break;
				}
			}
		}
		else
		{
			visible = true;
		}
		return visible;
	}

}
