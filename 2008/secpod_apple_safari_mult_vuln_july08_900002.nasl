##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_mult_vuln_july08_900002.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Apple Safari for Windows Multiple Vulnerabilities July-08
#
# Authors:
# Chandan S <schandan@secpod.com>
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

tag_impact = "Successful exploitation by attacker could lead to exposure of
        sensitive information, system access or denying the application and allow execution of
        arbitrary code.
 Impact Level : SYSTEM";

tag_affected = "Apple Safari versions prior to 3.1.2 on Windows (All).";

tag_insight = "The vulnerability exists due to,
        - improper handling of BMP and GIF images that can lead to disclosure of
          system memory contents.
        - handling of files that are downloaded from a website which is in
          Internet Explorer 7 Zone with the Launching applications and unsafe files set to
          Enable, or in the Internet Explorer 6 Local Intranet or Trusted sites zone causing
          safary to launch unsafe executables.
        - an error in handling JavaScript arrays that can lead to memory corruption.";


tag_summary = "The host is installed with Apple Safari Web Browser, which is
 prone to multiple vulnerabilities.";

tag_solution = "Update safary to version 3.1.2
 http://www.apple.com/support/downloads/";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900002");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(29412, 29413, 29835, 29835);
 script_cve_id("CVE-2008-1573", "CVE-2008-2306", "CVE-2008-2307");
 script_copyright("Copyright 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Apple Safari for Windows Multiple Vulnerabilities July-08");


 script_dependencies("secpod_reg_enum.nasl",
		     "secpod_apple_safari_detect_win_900003.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://support.apple.com/kb/HT2092");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/30801/");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/30775/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/1882");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Jun/1020330.html");
 exit(0);
}


 if(!get_kb_item("SMB/WindowsVersion")){
 	exit(0);
 }

 # Grep for Apple Safari Version < 3.1.2 (3.525.21.0)
 if(egrep(pattern:"^(2\..*|3\.(52[2-4]\..*|525\.([01][0-9]|20)\..*))$",
	  string:get_kb_item("AppleSafari/Version"))){
	security_message(0);
 }
