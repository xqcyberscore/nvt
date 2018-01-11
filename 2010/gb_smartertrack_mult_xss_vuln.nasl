##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smartertrack_mult_xss_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# SmarterTools SmarterTrack Cross-Site Scripting Vulnerabilities
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
###############################################################################

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "SmarterTools SmarterTrack version prior to 4.0.3504";

tag_insight = "The flaws are due to the input passed to the 'search' parameter in
  'frmKBSearch.aspx' and email address to 'frmTickets.aspx' is not properly
  sanitised before being returned to the user.";
tag_solution = "Upgrade to SmarterTools SmarterTrack version 4.0.3504.
  For updates refer to http://www.smartertools.com/smartertrack/help-desk-download.aspx";
tag_summary = "This host is running SmarterTools SmarterTrack and is prone
  Cross-site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801453");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2009-4994", "CVE-2009-4995");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("SmarterTools SmarterTrack Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36172");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52305");
  script_xref(name : "URL" , value : "http://holisticinfosec.org/content/view/123/45/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports(9996);

  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

smartPort = "9996";
if(!get_port_state(smartPort)){
  exit(0);
}

## Send and receive response
sndReq = string("GET /Main/Default.aspx HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
rcvRes = http_keepalive_send_recv(port:smartPort, data:sndReq);

## Confirm the application is SmarterTools SmarterTrack
if(">SmarterTrack" >< rcvRes )
{
  ## Try exploit and check response to confirm vulnerability
  sndReq = string("GET /Main/frmKBSearch.aspx?search=%3Cscript%3Ealert(%22OpenVAS" +
                         "-XSS-Testing%22)%3C/script%3E HTTP/1.1", "\r\n",
                          "Host: ", get_host_name(), "\r\n\r\n");
  rcvRes = http_send_recv(port:smartPort, data:sndReq);
  if(rcvRes =~ "HTTP/1\.. 200" && '<script>alert("OpenVAS-XSS-Testing")</script>' >< rcvRes){
    security_message(smartPort);
  }
}
