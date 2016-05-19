/* 
 * Copyright (C) 2007 Nate Nielsen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _X509_USAGES_H_
#define _X509_USAGES_H_


#define X509_USAGE_SERVER_AUTH		"1.3.6.1.5.5.7.3.1"
#define X509_USAGE_CLIENT_AUTH		"1.3.6.1.5.5.7.3.2"	
#define X509_USAGE_CODE_SIGNING		"1.3.6.1.5.5.7.3.3"	
#define X509_USAGE_EMAIL			"1.3.6.1.5.5.7.3.4"	
#define X509_USAGE_TIME_STAMPING	"1.3.6.1.5.5.7.3.8"	
#define X509_USAGE_IPSEC_ENDPOINT	"1.3.6.1.5.5.7.3.5"	
#define X509_USAGE_IPSEC_TUNNEL		"1.3.6.1.5.5.7.3.6"	
#define X509_USAGE_IPSEC_USER		"1.3.6.1.5.5.7.3.7"	
#define X509_USAGE_IKE_INTERMEDIATE	"1.3.6.1.5.5.8.2.2"	


#define MS_USAGE_TRUST_LIST_SIGNING			"1.3.6.1.4.1.311.10.3.1"	
#define MS_USAGE_TIME_STAMPING				"1.3.6.1.4.1.311.10.3.2"	
#define MS_USAGE_EFS						"1.3.6.1.4.1.311.10.3.4"	
#define MS_USAGE_DRIVER_VERIFICATION		"1.3.6.1.4.1.311.10.3.5"	
#define MS_USAGE_SYSTEM_VERIFICATION		"1.3.6.1.4.1.311.10.3.6"	
#define MS_USAGE_OEM_VERIFICATION			"1.3.6.1.4.1.311.10.3.7"	
#define MS_USAGE_EMBEDDED_VERIFICATION		"1.3.6.1.4.1.311.10.3.8"	
#define MS_USAGE_KEY_PACK					"1.3.6.1.4.1.311.10.6.1"	
#define MS_USAGE_LICENSE_SERVER				"1.3.6.1.4.1.311.10.6.2"	
#define MS_USAGE_SMART_CARD					"1.3.6.1.4.1.311.20.2.2"	
#define MS_USAGE_DIGITAL_RIGHTS				"1.3.6.1.4.1.311.10.5.1"	
#define MS_USAGE_QUALIFIED_SUBORDINATION	"1.3.6.1.4.1.311.10.3.10"	
#define MS_USAGE_KEY_RECOVERY				"1.3.6.1.4.1.311.10.3.11"	
#define MS_USAGE_DOCUMENT_SIGNING			"1.3.6.1.4.1.311.10.3.12"	
#define MS_USAGE_FILE_RECOVERY				"1.3.6.1.4.1.311.10.3.4.1"	
#define MS_USAGE_ROOT_SIGNER_LIST			"1.3.6.1.4.1.311.10.3.9"	
#define MS_USAGE_APPLICATION_POLICIES		"1.3.6.1.4.1.311.10.12.1"	
#define MS_USAGE_AD_EMAIL_REPLICATION		"1.3.6.1.4.1.311.21.19"	
#define MS_USAGE_CERTIFICATE_REQUEST_AGENT	"1.3.6.1.4.1.311.20.2.1"	
#define MS_USAGE_KEY_RECOVERY_AGENT			"1.3.6.1.4.1.311.21.6"	
#define MS_USAGE_CA_ENCRYPTION_CERTIFICATE	"1.3.6.1.4.1.311.21.5"	
#define MS_USAGE_LIFETIME_SIGNING			"1.3.6.1.4.1.311.10.3.13"	

#endif /* _X509_USAGES_H_ */
