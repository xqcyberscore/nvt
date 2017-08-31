###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_smtp_not_supported.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# SMTP Missing Support For STARTTLS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105091");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 6735 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-09-23 14:29:22 +0100 (Tue, 23 Sep 2014)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("SMTP Missing Support For STARTTLS");

 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_starttls_smtp.nasl");
 script_require_ports("Services/smtp", 25);
 script_mandatory_keys("SMTP/STARTTLS/not_supported");

 script_tag(name: "summary" , value: "The remote Mailserver does not support the STARTTLS command.");

 exit(0);
}


port = get_kb_item("SMTP/STARTTLS/not_supported/port");
if( ! port ) exit( 0 );

log_message( port:port, data:"The remote Mailserver does not support the STARTTLS command." );

exit( 0 );

