###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_ftp_anonymous_logins.nasl 9364 2018-04-06 07:33:03Z cfischer $
#
# Wrapper for Nmap FTP Anon NSE script.
#
# Authors:
# NSE-Script: Eddie Bell
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

tag_summary = "This script attempts to check if an FTP server allows anonymous logins.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) ftp-anon.nse";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801260");
  script_version("$Revision: 9364 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:33:03 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:16:51 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE: FTP Anon");
  script_category(ACT_GATHER_INFO);
    script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_family("Nmap NSE");

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

## Get FTP Ports
port = get_kb_item("Services/ftp");
if(!port){
  exit(0);
}

## Run nmap and Get the result
args = make_list("nmap", "-v", "--script=ftp-anon", "-p", port, get_host_ip());
res = pread(cmd: "nmap", argv: args);

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

  if("ftp-anon" >< result) {
    msg = string('Result found by Nmap Security Scanner (ftp-anon.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
