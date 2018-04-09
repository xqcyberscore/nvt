###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_ssh_hostkey.nasl 9364 2018-04-06 07:33:03Z cfischer $
#
# Wrapper for Nmap SSH Hostkey NSE script.
#
# Authors:
# NSE-Script: Sven Klemm
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

tag_summary = "This script attempts to get the target SSH server's key fingerprint
  and public key.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) ssh-hostkey.nse";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801633");
  script_version("$Revision: 9364 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:33:03 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-11-25 08:32:22 +0100 (Thu, 25 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE: SSH Hostkey");
  script_category(ACT_GATHER_INFO);
    script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Nmap NSE");
  script_add_preference(name:"ssh_hostkey :", value: "full;bubble;visual;all",type: "radio");

  script_mandatory_keys("Tools/Present/nmap");
  script_mandatory_keys("Tools/Launch/nmap_nse");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


## Required Keys
if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

## Get SSH Ports
port = get_kb_item("Services/ssh");
if(!port){
  exit(0);
}

argv =  make_list("nmap", "--script=ssh-hostkey.nse", "-p", port, get_host_ip());

## Get the preference
if( pref = script_get_preference("ssh_hostkey :")){
  argv = make_list(argv, "--script-args=ssh_hostkey="+pref);
}

## Run Nmap and get the result
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

  if("ssh-hostkey" >< result) {
    msg = string('Result found by Nmap Security Scanner (ssh-hostkey.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
