###############################################################################
# OpenVAS Vulnerability Test
#
# SSH Remote password cracking using ncrack
# svn co svn://svn.insecure.org/nmap-exp/ithilgore/ncrack
# Tested with SVN r14943.
#
# Based on hydra scripts by Michel Arboi <arboi@alussinan.org>
# 
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This plugin runs ncrack to find SSH accounts & passwords by brute force.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80105");
 script_version("$Revision: 10530 $");
 script_tag(name:"last_modification", value:"$Date: 2018-07-17 16:15:42 +0200 (Tue, 17 Jul 2018) $");
 name = "ncrack: SSH";
 script_name(name);
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 

 script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
 script_family("Brute force attacks");
 script_require_ports("Services/ssh", 22);
 script_dependencies("toolcheck.nasl", "gcf/remote-pwcrack-options.nasl", "find_service.nasl");
 script_mandatory_keys ("Tools/Present/ncrack", "Secret/pwcrack/logins_file", "Secret/pwcrack/passwords_file");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Exit if nasl version is too old (<2200)
if (! defined_func("script_get_preference_file_location"))
{
  log_message(port: 0, data: "NVT not executed because of an too old openvas-libraries version.");
  exit(0);
}

logins = get_kb_item("Secret/pwcrack/logins_file");
passwd = get_kb_item("Secret/pwcrack/passwords_file");
if (logins == NULL || passwd == NULL) exit(0);

port = get_kb_item("Services/ssh");
if (! port) port = 22;
if (! get_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/pwcrack/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/pwcrack/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/pwcrack/empty_password");
login_pass = get_kb_item("/tmp/pwcrack/login_password");
exit_asap = get_kb_item("/tmp/pwcrack/exit_ASAP");

dstaddr=get_host_ip();

i = 0;
argv[i++] = "ncrack";
argv[i++] = "-U"; argv[i++] = logins;
argv[i++] = "-P"; argv[i++] = passwd;

hostpart = "ssh://"+dstaddr+":"+port;

if (timeout > 0)
{
	hostpart=hostpart+",to="+timeout;
}

if (tasks > 0)
{
	hostpart=hostpart+",CL="+tasks;
}

argv[i++] = hostpart;

report = "";
results = pread(cmd: "ncrack", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: dstaddr+" "+port+"/tcp *ssh: *(.*) (.*)$");
  if (! isnull(v))
  {
    l = chomp(v[1]);
    p = chomp(v[2]);
    report = strcat(report, 'username: ', l, '\tpassword: ', p, '\n');
    set_kb_item(name: 'pwcrack/ssh/'+port, value: l + '\t' + p);
  }
}

if (report)
  security_message(port: port, 
    data: 'ncrack was able to break the following SSH accounts:\n' + report);
