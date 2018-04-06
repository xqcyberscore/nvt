##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_ssl_sec_bypass_vuln_win_900020.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Man-in-the-middle attacks or identity impersonation attacks are possible.
 Impact Level : Network";

tag_solution = "Apply the patch from,
 http://developer.pidgin.im/attachment/ticket/6500/nss-cert-verify.patc h";


tag_summary = "The host is running Pidgin, which is prone to Security Bypass
 Vulnerability";

tag_affected = "Pidgin Version 2.4.3 and prior on Windows (All).";
tag_insight = "The application fails to properly validate SSL (Secure Sockets Layer) 
        certificate from a server.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900020");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3532");
 script_bugtraq_id(30553);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Windows)");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://developer.pidgin.im/ticket/6500 ");
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 pidginVer = registry_get_sz(item:"DisplayVersion",
	     key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin");

 if(egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.[0-3])?))$", string:pidginVer)){
 	security_message(0);
 }
