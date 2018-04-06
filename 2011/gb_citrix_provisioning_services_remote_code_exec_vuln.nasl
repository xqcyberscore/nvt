###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_provisioning_services_remote_code_exec_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Citrix Provisioning Services 'streamprocess.exe'  Remote Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the SYSTEM user.
  Impact Level: Application/System";
tag_affected = "Citrix Provisioning Services version 5.6 and prior.";
tag_insight = "The flaw is due to an error in the 'streamprocess.exe' component when
  handling a '0x40020010' type packet. This can be exploited to cause a stack
  based buffer overflow via a specially crafted packet sent to UDP port 6905.";
tag_solution = "Upgrade to Citrix Provisioning Services version 5.6 SP1 or later,
  For updates refer to http://support.citrix.com/article/CTX127123";
tag_summary = "This host is installed with Citrix Provisioning Services and is
  prone to remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802221");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_bugtraq_id(45914);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Citrix Provisioning Services 'streamprocess.exe' Component Remote Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42954");
  script_xref(name : "URL" , value : "http://support.citrix.com/article/CTX127149");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-023/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_citrix_provisioning_services_detect.nasl");
  script_require_keys("Citrix/Provisioning/Services/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("Citrix/Provisioning/Services/Ver");
if(version)
{
  ## Check for Citrix Provisioning Services version 5.6 and prior.
  if(version_is_less_equal(version:version, test_version:"5.6.0")){
    security_message(0);
  }
}
