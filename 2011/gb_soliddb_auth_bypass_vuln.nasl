###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_soliddb_auth_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM solidDB User Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to bypass authentication.
  Impact Level: Application";
tag_affected = "IBM solidDB version before 4.5.181, 6.0.x before 6.0.1067,
  6.1.x and 6.3.x before 6.3.47, and 6.5.x before 6.5.0.3";
tag_insight = "The flaw exists within the 'solid.exe' process which listens by default on
  TCP ports 1315, 1964 and 2315. The authentication protocol allows a remote
  attacker to specify the length of a password hash. An attacker could bypass
  the authentication by specifying short length value.";
tag_solution = "Apply the patches from below link,
  https://www-304.ibm.com/support/docview.wss?uid=swg21474552";
tag_summary = "This host is running IBM solidDB and is prone to authentication bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801938");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1560");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM solidDB User Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66455");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg21474552");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_require_ports("Services/soliddb", 1315);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

## Get solidDB default port
port = get_kb_item("Services/soliddb");
if(!port){
  port=1315;
}

## check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version from kb
if(!ver = get_kb_item(string("soliddb/",port,"/version"))){
  exit(0);
}

version = eregmatch(pattern:"([0-9]+\.[0-9]+\.[0-9.]+)", string: ver);
if(version[1] != NULL){
  ver = version[1];
}

## Check the version less than 4.5.181
if(version_is_less(version:ver, test_version:"4.5.181"))
{
  security_message(port:port);
  exit(0);
}

## Check for the version 6.0.x before 6.0.1067
if(ver =~ "^6\.0\.*")
{
  if(version_is_less(version:ver, test_version:"6.0.1067"))
  {
    security_message(port:port);
    exit(0);
  }
}

## Check the version 6.1.x
if(ver =~ "^6\.1\.*")
{
  security_message(port:port);
  exit(0);
}

## Check the version 6.3.x before 6.3.47(06.30.0047)
if(ver =~ "^06\.3.*")
{
  if(version_is_less(version:ver, test_version:"06.30.0047"))
  {
    security_message(port:port);
    exit(0);
  }
}

## Check the version 6.5.x before 6.5.0.3
if(ver =~ "^6\.5\.*")
{
  if(version_is_less(version:ver, test_version:"6.5.0.3")){
    security_message(port:port);
  }
}
