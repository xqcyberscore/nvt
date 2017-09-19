##############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_CVE_2009_1195.nasl 7176 2017-09-18 12:01:01Z cfischer $
#
# Apache 'Options' and 'AllowOverride' Directives Security Bypass
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "Apache HTTP server is prone to a security-bypass vulnerability
   related to the handling of specific configuration directives.

   A local attacker may exploit this issue to execute arbitrary code
   within the context of the webserver process. This may result in
   elevated privileges or aid in further attacks.

   Versions prior to Apache 2.2.9 are vulnerable.";

tag_solution = "Updates are available. Please see http://httpd.apache.org/
   for more Information.";

if(description)
{
  script_id(100211);
  script_version("$Revision: 7176 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 14:01:01 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2009-1195");
  script_bugtraq_id(35115);
  script_name("Apache 'Options' and 'AllowOverride' Directives Security Bypass Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl", "secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35115");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

httpdPort = get_http_port(default:80);
if(!httpdPort){
  exit(0);
}

version = get_kb_item("www/" + httpdPort + "/Apache");
if(version != NULL){
  if(version_is_less(version:version, test_version:"2.2.9")){
    security_message(httpdPort);
  }
}
