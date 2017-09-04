###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_n_sjas_web_container_dos_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# Oracle GlassFish/System Application Server Web Container DOS Vulnerability
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

tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpuoct2011-330135.html

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation could allow malicious attackers to cause a denial
  of service.
  Impact Level: Application";
tag_affected = "Oracle GlassFish version 2.1.1, 3.0.1 and 3.1.1
  Oracle Java System Application Server version 8.1 and 8.2";
tag_insight = "The flaw is due to an unspecified error within the Web Container
  component, which allows remote users to cause denial of service conditions.";
tag_summary = "The host is running GlassFish/System Application Server and is
  prone to denial of service vulnerability.";

if(description)
{
  script_id(801997);
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_cve_id("CVE-2011-3559");
  script_bugtraq_id(50204);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Oracle GlassFish/System Application Server Web Container DOS Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/46524");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46523");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/70816");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1026222");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
  if(version_in_range(version: vers, test_version:"3.0", test_version2:"3.1.1") ||
     version_in_range(version: vers, test_version:"2.1", test_version2:"2.1.1"))
  {
    security_message(port:port);
    exit(0);
  }
}

ver = get_kb_item("Sun/Java/AppServer/Ver");
if(ver)
{
  ver = ereg_replace(pattern:"_", replace:".", string:ver);

  # Check for Java Application Server version 8.1 and 8.2
  if(version_is_equal(version:ver, test_version:"8.0.01") ||
     version_is_equal(version:ver, test_version:"8.0.02")){
    security_message(port:port);
  }
}
