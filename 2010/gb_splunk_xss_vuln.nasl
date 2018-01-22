###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_xss_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Splunk 'Referer' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "Splunk version 4.0 through 4.1.2";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'Referer' header before being returned to the user within a HTTP 404
  error message when using Internet Explorer.";
tag_solution = "Upgrade to Splunk version 4.1.3  or later,
  For updates refer to http://www.splunk.com/download";
tag_summary = "This host is running Splunk and is prone to Cross-Site Scripting
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801226");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-2429");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Splunk 'Referer' Header Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40187");
  script_xref(name : "URL" , value : "http://www.splunk.com/view/SP-CAAAFHY");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59517");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_require_ports("Services/www", 8000);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8000);
if(!get_port_state(port)) {
  exit(0);
}

vers = get_kb_item(string("www/", port, "/splunk"));
if(!isnull(vers))
{
  if(version_in_range(version: vers, test_version: "4.0", test_version2:"4.1.2")){
    security_message(port:port);
  }
}
