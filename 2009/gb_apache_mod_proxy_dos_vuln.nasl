###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_proxy_dos_vuln.nasl 4865 2016-12-28 16:16:43Z teissa $
#
# Apache 'mod_proxy_http.c' Denial Of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to cause Denial of Service
  to the legitimate user by CPU consumption.
  Impact Level: Application";
tag_affected = "Apache HTTP Server version prior to 2.3.3";
tag_insight = "The flaw is due to error in 'stream_reqbody_cl' function in 'mod_proxy_http.c'
  in the mod_proxy module. When a reverse proxy is configured, it does not properly
  handle an amount of streamed data that exceeds the Content-Length value via
  crafted requests.";
tag_solution = "Fixed in the SVN repository.
  http://svn.apache.org/viewvc?view=rev&revision=790587";
tag_summary = "This host is running Apache HTTP Server and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800827);
  script_version("$Revision: 4865 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-28 17:16:43 +0100 (Wed, 28 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2009-1890");
  script_bugtraq_id(35565);
  script_name("Apache 'mod_proxy_http.c' Denial Of Service Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35691");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1773");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=790587&r2=790586&pathrev=790587");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

httpdPort = get_http_port(default:80);
if(httpdPort == NULL){
  exit(0);
}

httpdVer = get_kb_item("www/" + httpdPort + "/Apache");
if(httpdVer == NULL){
  exit(0);
}

if(version_is_less(version:httpdVer, test_version:"2.3.3")){
  security_message(httpdPort);
}
