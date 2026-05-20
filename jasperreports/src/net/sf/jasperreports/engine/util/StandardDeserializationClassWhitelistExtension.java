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

import java.util.List;

import net.sf.jasperreports.engine.JRPropertiesMap;
import net.sf.jasperreports.engine.JRPropertiesUtil;
import net.sf.jasperreports.engine.JRPropertiesUtil.PropertySuffix;
import net.sf.jasperreports.extensions.ExtensionsRegistry;
import net.sf.jasperreports.extensions.ExtensionsRegistryFactory;
import net.sf.jasperreports.extensions.SingletonExtensionRegistry;

/**
 * Extension factory for registering deserialization class whitelists from properties.
 */
public class StandardDeserializationClassWhitelistExtension implements ExtensionsRegistryFactory
{

	@Override
	public ExtensionsRegistry createRegistry(String registryId, JRPropertiesMap properties)
	{
		StandardDeserializationClassWhitelist whitelist = new StandardDeserializationClassWhitelist();
		List<PropertySuffix> whitelistProps = JRPropertiesUtil.getProperties(properties, 
				DeserializationClassFilter.PROPERTY_PREFIX_CLASS_WHITELIST);
		for (PropertySuffix propertySuffix : whitelistProps)
		{
			whitelist.addWhitelist(propertySuffix.getValue());
		}
		return new SingletonExtensionRegistry<DeserializationClassWhitelist>(DeserializationClassWhitelist.class, whitelist);
	}

}
