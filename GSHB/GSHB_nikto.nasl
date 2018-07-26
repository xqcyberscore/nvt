###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_nikto.nasl 10616 2018-07-25 13:37:26Z cfischer $
#
# Starts nikto with Option -Tuning x016bc and write to KB
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.96044");
  script_version("$Revision: 10616 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:37:26 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Starts nikto with Option -Tuning x016bc and write to KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "httpver.nasl", "logins.nasl");

  script_tag(name:"summary", value:"This plugin uses nikto(1)to find weak CGI scripts
  and other known issues regarding web server security. It starts with the Option
  -Tuning x016bc and writes only OSVDB issues to the KB.");

  exit(0);
}

nikto = "";

if (  find_in_path("nikto.pl")  )
{
	nikto = "nikto.pl";
}
else if (  find_in_path("nikto")  )
{
	nikto = "nikto";
}
else
{
    text = 'Nikto could not be found in your system path.\n';
    text += 'OpenVAS was unable to execute Nikto and to perform the scan you
requested.\nPlease make sure that Nikto is installed and that nikto.pl or nikto is
available in the PATH variable defined for your environment.';
    log_message(port:0, proto: "IT-Grundschutz", data: text);
    set_kb_item(name:"GSHB/NIKTO", value:"error");
    exit(0);
}

user = get_kb_item("http/login");
pass = get_kb_item("http/login");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)){
  set_kb_item(name:"GSHB/NIKTO", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:string("Can't open Port " + port + " for Nikto test."));
  exit(0);
}

i = 0;
argv[i++] = nikto;

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

argv[i++] = "-h"; argv[i++] = get_host_ip();
argv[i++] = "-p"; argv[i++] = port;
argv[i++] = "-T"; argv[i++] = "x016bc";

encaps = get_port_transport(port);
if (encaps > ENCAPS_IP) argv[i++] = "-ssl";

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread(cmd: nikto, argv: argv, cd: 1);
if (! r){
  set_kb_item(name:"GSHB/NIKTO", value:"error");
  log_message(port:0, proto: "IT-Grundschutz", data:string("Nikto has no result!"));
  exit(0);
}

foreach l (split(r))
{
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if ('+ OSVDB' >< l)
    report += l;
}

if (!report) report = "none";

set_kb_item(name:"GSHB/NIKTO", value:report);
