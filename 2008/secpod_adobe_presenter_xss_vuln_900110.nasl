##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_presenter_xss_vuln_900110.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Adobe Presenter viewer.swf and loadflash.js XSS Vulnerability
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

tag_impact = "Execution of arbitrary HTML or Scripting code in the security
        context of the affected web site.
 Impact Level : Application";

tag_solution = "Upgrade to Adobe Presenter 7.0.1,
 http://www.adobe.com/downloads/";

tag_affected = "Adobe Presenter 6.x and 7.x";

tag_insight = "Input validation errors in the 'viewer.swf' and 'loadflash.js' files,
        which could be exploited by attackers to execute arbitrary scripting
        code in the user's browser session.";


tag_summary = "The host is running Adobe Presenter, which prone to to input
            validation errors which can be exploited by malicious people 
            to conduct cross-site scripting vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900110");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30615);
 script_cve_id("CVE-2008-3515","CVE-2008-3516");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Web application abuses");			
 script_name("Adobe Presenter viewer.swf and loadflash.js XSS Vulnerability");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31432/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2322");
 script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-17.html");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");

 if(!(get_kb_item("SMB/WindowsVersion"))){
        exit(0);
 }

 if(!registry_key_exists(key:"SOFTWARE\Adobe\Presenter")){
        exit(0);
 }

 adobeVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
				 "\Uninstall\Adobe Presenter 6",
			     item:"DisplayVersion");
 if(!adobeVer)
 {
	adobeVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\Uninstall\Adobe Presenter 7",
                             item:"DisplayVersion");
	if(!adobeVer){
		exit(0);
	}
 }

 if(egrep(pattern:"^(6\..*|7\.0)$", string:adobeVer)){
        	security_message(0);
 }
