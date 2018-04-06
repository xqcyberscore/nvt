###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_metasploit_framework_loc_prev_escl_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Metasploit Framework Local Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the local users to execute arbitrary code
  with LocalSystem privileges when the 'frameworkPostgreSQL' service is
  restarted.
  Impact Level: Application.";
tag_affected = "Metasploit Framework version 3.5.1 and prior on windows.";
tag_insight = "The flaw is due to the application being installed with insecure
  filesystem permissions in the system's root drive. This can be exploited
  to create arbitrary files in certain directories.";
tag_solution = "Upgrade Metasploit Framework 3.5.2 or later,
  For updates refer to http://www.metasploit.com/framework/download/";
tag_summary = "This host is installed with Metasploit Framework and is prone to
  local privilege escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902294");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_bugtraq_id(46300);
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1056", "CVE-2011-1057");
  script_name("Metasploit Framework Local Privilege Escalation Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43166");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0371");
  script_xref(name : "URL" , value : "http://blog.metasploit.com/2011/02/metasploit-framework-352-released.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_metasploit_framework_detect_win.nasl");
  script_require_keys("Metasploit/Framework/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get the version from kb
mfVer = get_kb_item("Metasploit/Framework/Win/Ver");
if(mfVer)
{
  if(version_is_less(version:mfVer, test_version:"3.5.2")){
    security_message(0);
  }
}
