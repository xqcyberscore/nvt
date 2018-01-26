###############################################################################
# OpenVAS Vulnerability Test
# $Id: cvspserver_version.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# CVS pserver version Detection
#
# Authors:
# Michael Meyer
# LSS Security Team <http://security.lss.hr>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH / LSS <http://www.lss.hr>
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

tag_summary = "Overview : This script retrieves the version of CVS pserver
  and saves the result in KB.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100288");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("CVS pserver version");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH / LSS");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/cvspserver", 2401);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100288";
SCRIPT_DESC = "CVS pserver version";

port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;
if(!get_port_state(port))exit(0);

function scramble(pass) {
# see http://www.delorie.com/gnu/docs/cvs/cvsclient_4.html
# for scramble information

 local_var x, scrambled, c;
 
# character substitution table
 c[33] = 120;	# !
 c[34] = 53;	# "
 c[37] = 109;	# %
 c[38] = 72; 	# &
 c[39] = 108; 	# '
 c[40] = 70;	# (
 c[41] = 64;	# )
 c[42] = 76;	# *
 c[43] = 67;	# +
 c[44] = 116;	# ,
 c[45] = 74;	# -
 c[46] = 68;	# .
 c[47] = 87;	# /
 c[48] = 111;	# 0
 c[49] = 52;	# 1
 c[50] = 75;	# 2
 c[51] = 119;	# 3
 c[52] = 49;	# 4
 c[53] = 34;	# 5
 c[54] = 82;	# 6
 c[55] = 81;	# 7
 c[56] = 95;	# 8
 c[57] = 65;	# 9
 c[58] = 112;	# :
 c[59] = 86;	# ;
 c[60] = 118;	# <
 c[61] = 110;	# =
 c[62] = 122;	# >
 c[63] = 105;	# ?
 c[65] = 57;	# A
 c[66] = 83;	# B
 c[67] = 43;	# C
 c[68] = 46;	# D
 c[69] = 102;	# E
 c[70] = 40;	# F
 c[71] = 89;	# G
 c[72] = 38;	# H
 c[73] = 103;	# I
 c[74] = 45;	# J
 c[75] = 50;	# K
 c[76] = 42;	# L
 c[77] = 123;	# M
 c[78] = 91;	# N
 c[79] = 35;	# O
 c[80] = 125;	# P
 c[81] = 55;	# Q
 c[82] = 54;	# R
 c[83] = 66;	# S
 c[84] = 124;	# T
 c[85] = 126;	# U
 c[86] = 59;	# V
 c[87] = 47;	# W
 c[88] = 92;	# X
 c[89] = 71;	# Y
 c[90] = 115;	# Z
 c[95] = 56;	# _
 c[97] = 121;	# a
 c[98] = 117;	# b
 c[99] = 104;	# c
 c[100] = 101;	# d
 c[101] = 100;	# e
 c[102] = 69;	# f
 c[103] = 73;	# g
 c[104] = 99;	# h
 c[105] = 63;	# i
 c[106] = 94;	# j
 c[107] = 93;	# k
 c[108] = 39;	# l
 c[109] = 37;	# m
 c[110] = 61;	# n
 c[111] = 48;	# o
 c[112] = 58;	# p
 c[113] = 113;	# q
 c[114] = 32;	# r
 c[115] = 90;	# s
 c[116] = 44;	# t
 c[117] = 98;	# u
 c[118] = 60;	# v
 c[119] = 51;	# w
 c[120] = 33;	# x
 c[121] = 97;	# y
 c[122] = 62;	# z

 for (x=0; x<strlen(pass); x++) {
  scrambled += raw_string(c[ord(pass[x])]);
 }

return scrambled;
}

logins      = make_list("anonymous", "anoncvs");
passwords   = make_list("","anoncvs", "anon");
dirs        = make_list("/var/lib/cvsd/","/cvs", "/cvsroot", "/home/ncvs", "/usr/local/cvs","/u/cvs","/usr/local/cvsroot");

foreach dir (dirs) {
 foreach login (logins) {
  foreach password (passwords) {

    soc = open_sock_tcp(port);
    if(!soc)exit(0);

    req = string("BEGIN AUTH REQUEST\n", dir, "\n", login,"\n", "A", scramble(password),"\n", "END AUTH REQUEST\n");
    send(socket:soc, data:req);
    buf = recv_line(socket:soc, length:4096);

    if("I LOVE YOU" >< buf) {

      set_kb_item(name:string("cvs/", port, "/login"), value:login);
      set_kb_item(name:string("cvs/", port, "/pass"),  value:password);
      set_kb_item(name:string("cvs/", port, "/dir"),   value:dir);

      send(socket:soc, data:string("Root ", dir, "\nversion\n"));
      buf = recv_line(socket:soc, length:4096);

      if(egrep(string: buf, pattern: "CVS", icase:TRUE)) {

	version = eregmatch(string:buf, pattern:"([0-9.]+)"); 

	if(!isnull(version[1])) {
            set_kb_item(name:string("cvs/", port, "/version"), value:version[1]);
   
            ## build cpe and store it as host_detail
            cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:cvs:cvs:");
            if(!isnull(cpe))
               register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

	    exit(0);
	} else {
            exit(0);;
          } 	  
      } else {
          exit(0);
        }
    } else {
       continue; 
      }   
  }
 } 
}

exit(0);
