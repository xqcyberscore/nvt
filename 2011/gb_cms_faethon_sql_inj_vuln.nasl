###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_faethon_sql_inj_vuln.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# CMS Faethon 'info.php' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802162");
  script_version("$Revision: 7052 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2009-5094");
  script_bugtraq_id(33775);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CMS Faethon 'info.php' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30098");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48758");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8054/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to manipulate SQL
  queries by injecting arbitrary SQL code.

  Impact Level: Application");
  script_tag(name : "affected" , value : "CMS Faethon version 2.2 Ultimate.");
  script_tag(name : "insight" , value : "The flaw is due to input passed to the 'item' parameter in
  'info.php' is not properly sanitised before being used in SQL queries.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running CMS Faethon and is prone to SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list_unique("/faethon", "/22_ultimate", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  res = http_get_cache(item: dir + "/index.php", port:port);

  ## Confirm the application
  if('>Powered by <' >< res && '>CMS Faethon' >< res)
  {
    ## Try SQL injection and check the response to confirm vulnerability
    url = dir + "/info.php?item='";
    if(http_vuln_check(port:port, url:url, pattern:'You have an error in' +
                                  ' your SQL syntax;'))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);