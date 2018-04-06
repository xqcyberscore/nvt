###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_geoserver_mem_corr_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# GeoServer Memory Corruption Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful attacks may lead to failure to report service exception if the code
  encoding the output calls flush() before having written the full contents to
  the output.
  Impact Level: Application";
tag_affected = "GeoServer version before 1.6.1 and 1.7.0-beta1.";
tag_insight = "Error exists when PartialBufferOutputStream2 flushes the buffer contents even
  when it is handling an 'in memory buffer', which prevents the reporting of a
  service exception, with unknown impact and attack vectors.";
tag_solution = "Upgrade to version 1.6.1 or 1.7.0-beta1 or later.
  http://geoserver.org/display/GEOS/Download";
tag_summary = "This host is installed with GeoServer and is prone to Memory
  Corruption vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900946");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7227");
  script_name("GeoServer Memory Corruption Vulnerability");


  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_geoserver_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://jira.codehaus.org/browse/GEOS-1747");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

geoPort = get_http_port(default:8080);
if(!geoPort){
  exit(0);
}

geoVer = get_kb_item("www/" + geoPort + "/GeoServer");
geoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:geoVer);

if(geoVer[1] != NULL)
{
  if(version_is_less(version:geoVer[1], test_version:"1.6.1") ||
     version_in_range(version:geoVer[1], test_version:"1.7",
                                        test_version2:"1.7.0.beta")){
    security_message(geoPort);
  }
}
