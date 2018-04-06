###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_glassfish_n_sjas_corba_orb_comp_dos_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Oracle GlassFish/Java System Application Server CORBA ORB Subcomponent DoS Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation could allow malicious attackers to cause a denial
  of service.
  Impact Level: Application";
tag_affected = "Oracle GlassFish version 2.1.1, 3.0.1 and 3.1.2
  Oracle Java System Application Server version 8.1 and 8.2";
tag_insight = "The flaw is caused due to an unspecified error within the CORBA ORB
  subcomponent, which allows remote users to cause a denial of service
  condition.";
tag_summary = "This host is running Oracle GlassFish/Java System Application
  Server and is prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903044");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-3155");
  script_bugtraq_id(56073);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-10-25 16:57:46 +0530 (Thu, 25 Oct 2012)");
  script_name("Oracle GlassFish/Java System Application Server CORBA ORB Subcomponent DoS Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/51017/");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("GlassFish_detect.nasl", "secpod_sun_java_app_serv_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));
if(vers)
{
  if(version_is_equal(version: vers, test_version:"3.0.1")||
     version_is_equal(version: vers, test_version:"3.1.2")||
     version_is_equal(version: vers, test_version:"2.1.1"))
  {
    security_message(port:port);
    exit(0);
  }
}

ver = get_kb_item("Sun/Java/AppServer/Ver");
if(ver)
{
  # Check for Java Application Server version 8.1 and 8.2
  if(version_is_equal(version:ver, test_version:"8.1") ||
     version_is_equal(version:ver, test_version:"8.2")){
    security_message(port:port);
  }
}
