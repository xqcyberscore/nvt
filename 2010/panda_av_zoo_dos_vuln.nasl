###################################################################
# OpenVAS Vulnerability Test
#
# Panda AntiVirus Zoo Denial of Service Vulnerability
#
# LSS-NVT-2010-038
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

tag_solution = "An update has been issued on April 02 2007 to 
  solve this vulnerability through the regular update mechanism.";
tag_summary = "Panda Software Antivirus/Internet Security before 20070402 allows 
  remote attackers to cause a denial of service (infinite loop) via
  a ZOO archive with a direntry structure that points to a previous file.";

if(description)
{
  script_id(102049);
  script_version("$Revision: 8217 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 14:24:55 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-1670");
  script_bugtraq_id(23823);
  script_name("Panda AntiVirus Zoo Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/467646/100/0/threaded");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/25152");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Denial of Service");
  script_dependencies("panda_av_update_detect.nasl");
  script_mandatory_keys("Panda/LastUpdate/Available");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

  exit(0);
}

include ("version_func.inc"); #version checking library

vuln = 0; #if vulnerable, vuln = 1
vuln_update = "04-02-2007";
#software not updated after this date is vulnerable

#This part of code converts the Vuln_update date in a format 
#that is checkable using the version_func.inc constructs
vuln_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$",
                  replace:"\3.\2.\1",
                  string:vuln_update);

# Check for Panda Antivirus 2006/2007
  
if (last_update = get_kb_item("Panda/AntiVirus/LastUpdate")) {

  last_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$",
                    replace:"\3.\2.\1",
                    string:last_update);
  
  vuln = version_is_less(version: last_update,
  test_version:vuln_update);
}

# Check for Panda Internet Security 2006/2007

if (last_update = get_kb_item("Panda/InternetSecurity/LastUpdate")) {

  last_update = ereg_replace(pattern:"^(.*)-(.*)-(.*)$",
                    replace:"\3.\2.\1",
                    string:last_update);
  
  vuln = version_is_less(version: last_update,
  test_version:vuln_update);
}
  
if(vuln)
{
  security_message(0);
  exit(0);
}

