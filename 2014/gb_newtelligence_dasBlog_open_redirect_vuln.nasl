###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_newtelligence_dasBlog_open_redirect_vuln.nasl 3524 2016-06-15 13:10:28Z benallard $
#
# Newtelligence dasBlog 'url' Parameter Open Redirect Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804875");
  script_version("$Revision: 3524 $");
  script_cve_id("CVE-2014-7292");
  script_bugtraq_id(70654);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 15:10:28 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-11-04 11:40:26 +0530 (Tue, 04 Nov 2014)");
  script_name("Newtelligence dasBlog 'url' Parameter Open Redirect Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with Newtelligence
  dasBlog and is prone to open redirect vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites.");

  script_tag(name: "insight" , value:"The error exists as the application does not
  validate the 'url' parameter upon submission to the ct.ashx script.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Newtelligence dasBlog versions
  2.1 (2.1.8102.813), 2.2 (2.2.8279.16125), and 2.3 (2.3.9074.18820).");

  script_tag(name: "solution" , value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a
  newer release, disable respective features, remove the product or replace
  the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/97667");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/128749");
  script_xref(name : "URL" , value : "http://www.tetraph.com/blog/cves/cve-2014-7292-newtelligence-dasblog-open-redirect-vulnerability/");

  script_summary("Check if Newtelligence dasBlog is vulnerable to open redirect");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
blogPort = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
blogPort = get_http_port(default:80);

## Iterate over possible paths
foreach dir (make_list_unique("/dasBlog", "/blog", "/", cgi_dirs(port:blogPort)))
{

  if(dir == "/") dir = "";

  ## Construct GET Request
  sndReq = http_get(item: string(dir+ "/Login.aspx"),  port:blogPort);
  rcvRes = http_keepalive_send_recv(port:blogPort, data:sndReq);

  ##Confirm Application
  if(rcvRes && rcvRes =~ "Powered by.*newtelligence dasBlog")
  {
    ## Vulnerable Url
    url = dir + "/ct.ashx?&url=http://www.example.com";

    sndReq = http_get(item: url,  port:blogPort);
    rcvRes = http_keepalive_send_recv(port:blogPort, data:sndReq);

    ## Confirm exploit worked by checking the response
    if(rcvRes && rcvRes =~ "HTTP/1.. 302" &&
       "Location: http://www.example.com" >< rcvRes)
    {
      security_message(port:blogPort);
      exit(0);
    }
  }
}

exit(99);
