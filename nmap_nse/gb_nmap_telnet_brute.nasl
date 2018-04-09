###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_telnet_brute.nasl 9364 2018-04-06 07:33:03Z cfischer $
#
# Wrapper for Nmap Telnet Brute NSE script.
#
# Authors:
# NSE-Script: Eddie Bell, Ron Bowes
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
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

tag_summary = "This script attempts to get Telnet login credentials by guessing
  usernames and passwords.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) telnet-brute.nse.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801670");
  script_version("$Revision: 9364 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:33:03 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-12-27 14:48:59 +0100 (Mon, 27 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE: Telnet Brute");
  script_category(ACT_ATTACK);
    script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Nmap NSE");
  script_add_preference(name: "userdb :", value: "",type: "entry");
  script_add_preference(name: "passdb :", value: "",type: "entry");
  script_add_preference(name: "unpwdb.passlimit :", value: "",type: "entry");
  script_add_preference(name: "unpwdb.timelimit :", value: "",type: "entry");
  script_add_preference(name: "unpwdb.userlimit :", value: "",type: "entry");
  script_mandatory_keys("Tools/Present/nmap");
  script_mandatory_keys("Tools/Launch/nmap_nse");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


## Check for Required Keys
if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

## Get Telnet Ports
port = get_kb_item("Services/telnet");
if(!port){
   port = 23;
}

if(!get_port_state(port)){
  exit(0);
}

argv = make_list("nmap", "--script=telnet-brute.nse", "-p", port, get_host_ip());

## Get the preferences
i = 0;

if( pref = script_get_preference("userdb :")){
  args[i++] = "userdb="+pref;
}

if( pref = script_get_preference("passdb :")){
  args[i++] = "passdb="+pref;
}

if( pref = script_get_preference("unpwdb.passlimit :")){
  args[i++] = "unpwdb.passlimit="+pref;
}

if( pref = script_get_preference("unpwdb.timelimit :")){
  args[i++] = "unpwdb.timelimit="+pref;
}

if( pref = script_get_preference("unpwdb.userlimit :")){
  args[i++] = "unpwdb.userlimit="+pref;
}

if(i > 0)
{
  scriptArgs= "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv,scriptArgs);
}

## Run nmap and Get the result
res = pread(cmd: "nmap", argv: argv);
if(res)
{
  foreach line (split(res))
  {
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("telnet-brute" >< result) {
    msg = string('Result found by Nmap Security Scanner (telnet-brute.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
