###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_old_auth_user_enum_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# MySQL Authentication Error Message User Enumeration Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802046");
  script_version("$Revision: 3566 $");
  script_bugtraq_id(56766);
  script_cve_id("CVE-2012-5615");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-12-07 16:13:41 +0530 (Fri, 07 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MySQL Authentication Error Message User Enumeration Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51427");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23081");
  script_xref(name : "URL" , value : "https://mariadb.atlassian.net/browse/MDEV-3909");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=882608");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/02/3");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/02/4");

  script_summary("Determine if MySQL is vulnerable to user enumeration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("MySQL/installed");
  script_tag(name : "impact" , value : "Successful exploitation allows attackers to obtain valid
  usernames, which may aid them in brute-force password cracking or other attacks.

  Impact Level: Application");
  script_tag(name : "affected" , value : "MySQL version 5.5.19 and possibly other versions
  MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66 and possibly other versions");
  script_tag(name : "insight" , value : "Mysql server will respond with a different message than Access
  Denied, when attacker authenticates using an incorrect password with the old
  authentication mechanism mysql 4.x and below to a mysql 5.x server.");
  script_tag(name : "solution" , value : "For Maria DB upgrade to 5.5.29, 5.3.12, 5.2.14 or later.
  For updates refer to https://mariadb.org/

  For MySQL apply the updates from vendor, http://www.mysql.com/");
  script_tag(name : "summary" , value : "The host is running MySQL and is prone to user enumeration
  vulnerability.");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

soc = "";
buf = "";
res2 = "";
sql_port = 0;
initial_res = "";
user_enum_list = "";
mysqlVer = 0;

## Get MySQL Port
sql_port = get_app_port(cpe:CPE);
if(!sql_port){
  sql_port = 3306;
}

## Check port state
if(!get_port_state(sql_port)){
  exit(0);
}

## Get version
if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort))
{
  CPE = "cpe:/a:oracle:mysql";
  if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){ 
    exit(0);
  }
}

## Check for vulnerable versions
if(version_is_less_equal(version:mysqlVer, test_version:"5.5.19"))
{
  report = 'The following users could be enumerated:\n\n';
  found = 0;

  ## Usernames to enumerate
  user_enum_list = make_list("root", "admin", "test");

  ## Need different connection for each user
  foreach user (user_enum_list)
  {
    ## Open socket
    soc = open_sock_tcp (sql_port);
    if(!soc){
      exit(0);
    }

    ## Initial response
    initial_res = recv(socket:soc, length:1024);
    if(!initial_res || "mysql_native_password" >!< initial_res){
      close(soc);
      exit(0);
    }

    ## Construct old authentication mechanism from mysql 4.x
    ## with incorrect password
    buf = '\x13\x00\x00\x01\x8d\x00\x00\x00\x00' + user +
    '\x00\x50\x4e\x5f\x51\x55\x45\x4d\x45\x00';
    send(socket:soc, data:buf);
    res2 = recv(socket:soc, length:1024);
    close(soc);

    ## Check if mysql is vulnerable to user enumeration
    if("Client does not support authentication protocol" >< res2 &&
       "consider upgrading MySQL client" >< res2 &&
       "Access denied for user" >!< res2 )
    {
      found = 1;
      report += user + '\n';
    }
  }

  if(found) 
  {
    security_message(port:sql_port, data:report);
    exit(0);
  }
}
