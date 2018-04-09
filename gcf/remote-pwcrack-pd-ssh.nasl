###############################################################################
# OpenVAS Vulnerability Test
#
# SSH Remote password cracking using phrasen|drescher
# http://www.leidecker.info/projects/phrasendrescher/
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

tag_summary = "This plugin runs phrasen/drescher to find SSH accounts & passwords by brute force.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80106"); 
 script_version("$Revision: 9367 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:37:00 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-08-10 08:41:48 +0200 (Mon, 10 Aug 2009)");
 name = "phrasen|drescher: SSH";
 script_name(name);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2009 Vlatko Kosturjak");
 script_family("Brute force attacks");
 script_require_ports("Services/ssh", 22);
 script_dependencies("toolcheck.nasl", "remote-pwcrack-options.nasl", "find_service.nasl");
 script_mandatory_keys("Tools/Present/pd", "Secret/pwcrack/logins_file", "Secret/pwcrack/passwords_file");
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
argv[i++] = "pd";
argv[i++] = "ssh";
argv[i++] = "-P"; argv[i++] = port;
argv[i++] = "-U"; argv[i++] = logins;
argv[i++] = "-d"; argv[i++] = passwd;
s = "";
if (empty) s = "n";
if (login_pass) s+= "s";
if (s)
{
  argv[i++] = "-e"; argv[i++] = s;
}

# not implemented in pd
# if (exit_asap) argv[i++] = "-f";
#

# not implemented in pd
# if (timeout > 0)
# {
# argv[i++] = "-w";
#  argv[i++] = timeout;
# }

if (tasks > 0)
{
  argv[i++] = "-w";
  argv[i++] = tasks;
}

argv[i++] = "-t"; argv[i++] = dstaddr;

report = "";
results = pread(cmd: "pd", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: "password for '(.*)' on "+dstaddr+": *(.*)$");
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
    data: 'phrasen|drescher was able to break the following SSH accounts:\n' + report);
