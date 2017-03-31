###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers_setting.nasl 4841 2016-12-22 13:26:09Z cfi $
#
# SSL/TLS: Cipher Settings
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

include("secpod_ssl_ciphers.inc");

cipher_arrays = make_list( keys( sslv3_tls_ciphers ) );

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900238");
  script_version("$Revision: 4841 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-22 14:26:09 +0100 (Thu, 22 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Cipher Settings");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("SSL and TLS");

  foreach c ( keys( cipher_arrays ) )
  {
    v = FALSE;

    n = split( cipher_arrays[c], sep:" : ", keep:FALSE );
    if( isnull( n[0] ) || isnull( n[1] ) ) continue;

    if( "Weak cipher" >< n[1] )
      v = "Weak cipher;Null cipher;Medium cipher;Strong cipher";

    else if( "Null cipher" >< n[1] )
      v = "Null cipher;Weak cipher;Medium cipher;Strong cipher";

    else if( "Medium cipher" >< n[1] )
      v = "Medium cipher;Null cipher;Weak cipher;Strong cipher";

    else if( "Strong cipher" >< n[1] )
      v = "Strong cipher;Null cipher;Weak cipher;Medium cipher";

    else
      continue;

    if( v )
      script_add_preference( name:n[0], type:"radio", value:v );
  }

  script_tag(name:"summary", value:"This plugin Set SSL Cipher Settings.

  This plugin will gets the ssl cipher settings from user preference and
  sets into the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

foreach c( keys( cipher_arrays ) ) {

  n = split( cipher_arrays[c], sep:" : ", keep:FALSE );
  if( isnull( n[0] ) || isnull( n[1] ) ) continue;

  v = script_get_preference( n[0] );
  if( ! v ) continue;

  if( v >!< n[1] )
    set_kb_item( name:'ssl/ciphers/override/' + n[0] + ' : ' + n[1], value: v );
}
