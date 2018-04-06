###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_diagnostics_server_magentservice_bof_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Upgrade to HP LoadRunner 11.0 patch4 or later,
For updates refer to http://www.hp.com/ ";

tag_impact = "Successful exploitation may allow remote attackers to execute
arbitrary code within the context of the application or cause a denial of service
condition.

Impact Level: System/Application";

tag_affected = "HP Diagnostics Server 9.00";

tag_insight = "The flaw is due to an error within the magentservice.exe process
when processing a specially crafted request sent to TCP port 23472 and causing
a stack-based buffer overflow.";

tag_summary = "This host is running HP Diagnostics Server and is prone to
buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802386");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4789");
  script_bugtraq_id(51398);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-01 14:14:14 +0530 (Wed, 01 Feb 2012)");
  script_name("HP Diagnostics Server 'magentservice.exe' Buffer Overflow Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47574/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Jan/88");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-016/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_require_ports("Services/www", 2006, 23472);
  script_require_keys("hpdiagnosticsserver/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## HP Diagnostics Server and magentservice port
hpdsPort = get_http_port(default:2006);
magentPort = 23472;

if(!get_port_state(hpdsPort) || !get_port_state(magentPort)){
  exit(0);
}

##Get Version from KB
hpdsVer = get_kb_item("www/" + hpdsPort+ "/HP/Diagnostics_Server/Ver");

if(hpdsVer)
{
  if(version_is_equal(version:hpdsVer, test_version:"9.00")){
    security_message(magentPort);
  }
}
