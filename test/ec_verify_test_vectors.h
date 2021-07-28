/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

const int VERIFICATION_FAILED = 0;
const int VERIFICATION_SUCCESS = 1;
const int ERROR_NOT_CANONICALIZED = -1;

enum HASH_FUNCTION_ID { SHA_224, SHA_256, SHA_384, SHA_512 };

struct test_vector {
  const char data[257];
  const char public_key[129];
  const char signature_r[65];
  const char signature_s[65];
  const enum HASH_FUNCTION_ID hash_function_id;
  int result;
};

//  This test runs test vectors from
// https://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip
//
// The following sets have been copied from SigVer.rsp:
// [P-256,SHA-224], [P-256,SHA-256], [P-256,SHA-384], [P-256,SHA-512]
struct test_vector test_vectors[] = {
    {.data =
         {"3a9fd6b13337d9fd995d6e011e41c0bd24a7b068e8caa2f8ba10cb5b852e4f82c2d5"
          "176542a87668df5c6dda62ad47067e3bf7bf7f0defa57d996a1b40b22416bbb00953"
          "2b5e29d995c74defdd3824847e7ce473353f9825331fbd0aed174f6ec2c8c4c7f05d"
          "7c66304f09745acee5708e31770d9edd997753c74dff1b0507df"},
     .public_key =
         {"843f6d83d777aac75b758d58c670f417c8deea8d339a440bb626114318c34f29"
          "83e0c70008521c8509044b724420463e3478e3c91874d424be44413d1ce555f3"},
     .signature_r =
         {"d08e9a5db411019d826b20ac889227ed245503a6d839494db1e8d7995a6b245b"},
     .signature_s =
         {"8d46a204054125d0dc776ab1055302ec4eb0f20b90bca6d205f21d3cefd29097"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"a122dd3120879b6d288f1a4fce115899fa5a4a273621b022429284df2905a5f00eec"
          "eb4c3d57d17f1092b8bd11aac2768f69e82d4698170a028fe8b01625656eab963d07"
          "409280ebeaa12222adeab1e068015347fcf208d50d409c40913a85e6d0b8b8b65a70"
          "c10077e79be52286ee767018d9b1528e92014f5c8e11b4be9042"},
     .public_key =
         {"f08b56f73f7a0e098444f6f0a02ad81ce0b914a11cafa15893d1c84704e1c564"
          "bbee9aeb91cdc2d1d1437b4168df73acfd64e8b02962b14c85e67187e1ef80a4"},
     .signature_r =
         {"71b3ec982725a007ac18a5cf60587e1fd1beb57685a1f9df3cddd9df25dcbc18"},
     .signature_s =
         {"407e41217325f92f8a031cfcc4eb64c1a4b17b0a7459c254af754a7ea9eac997"},
     .hash_function_id = SHA_224,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"f8c9f5e424bc4fd18b6d103ad110f1c33976c337b0f8bb98ac936ce172bf218256c5"
          "f71a08d3365ee3498193d916065033c323827a0acb1cfc1f09ce40005b9cecc316f3"
          "cedd3da420c90a41a27c49f060588000ff2d26c77d830b46bcb6d4a5ffdb4702f575"
          "691b6b75fb1fbb73b5a03cd773c97ff7aff33d90a6ab9a4890de"},
     .public_key =
         {"0b688e761e1ddda2305e002809da65bf5916dfe1356a5b99b61f5576a9b90efa"
          "90ec958e2e3a676e7bbf8e9394f72742875836125a317b0ae38374953f746a91"},
     .signature_r =
         {"ef89df3bbf079fb250f7e882c4f85c0023fc3804e862d9ef4d9530a15f1013f0"},
     .signature_s =
         {"4ba985e900e6737b8e07eac638f7b38277ead4faee6d2076a2eee90fd2a6bf0f"},
     .hash_function_id = SHA_224,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"45a7186fb5a3b99dbb2f68bbd7f0afd1f49dd904a0f2a7899bc570f52b1f6434db43"
          "242cffe43b9053fdaac409c6be10d7c0ef64d7530b34948209c76aefca42c5c4ece2"
          "30640dd98da353261a34268a47aebf39f7f2b5ecb96bbcba3d6416a80124c6008f2c"
          "4dfc4f071d033228b9054a58c501a827bac237e8f92e064df60b"},
     .public_key =
         {"0b64480783e260e1e9caef37b4cc9c650d2d57e2c594b1106314843d8d7ab74e"
          "29d373d8522deffe40055aef539f53f38937eb799b44f05a8d8c0b381f12907f"},
     .signature_r =
         {"c5c26b0b21eef0f7a0f1cff38d0079d890376759369b01d8d8e959c1c785e203"},
     .signature_s =
         {"fecc400bf0deab99d87da168b9d0dd31d2dfa3435b0fe9d38b5fb8efd45195a4"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (2 - R changed)
    {.data =
         {"5201328490b8f88a1bd31e16359e9a0770691313da5140575ca460d398f3d26ae4fa"
          "32fcc4aa522c9597333a20bbc0986235410f861522584a382b7c197a9f90a6742e18"
          "cd091f68106024b5beba0a67fa4699f7d0310c9c6d49ce37ce1e9653b3b77eb7a17a"
          "58676c2d9c765ec5077a7562d3c697cbc9a6f5e50e0819405afb"},
     .public_key =
         {"7f78a8fd880c509940e2b83de67c9ab553ab91489bae75cdc1d5b523b06ab7f5"
          "7786aee7032c373cdfad7d9ddb6fa09a026f6da30fd477ab014d30a289d542a1"},
     .signature_r =
         {"c93ada69db326f76b1362d610cb8bcc6e7ef1dc03d3d11367e153c0e39d5dc86"},
     .signature_s =
         {"d0c02c71b14ef7a4af4e23bd207ce98449f5d6e7e5b3ec8cbbca9549e97d379d"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"2c3af4a121b896c59437abf6e58c21ca6cc45af7a405515a7a253554264735dbd613"
          "9cf27316c6d0454c5729ee770116c267844e4a4e72bf6d3a4a050cf274bdd9730235"
          "a6bf26e6731b2e72afe81046849706f55f8d3baccb6b321123f176d6e586daf01d90"
          "3843b396fe7f3e4015c464363f54aeaff6e719267392110b37d3"},
     .public_key =
         {"e58cdc207c56f62e0bb7c0b55b7f7236a6b308f8fc4de3e61cdb3bf20ad2f62c"
          "6056c0ee827e85ba284838954d0c6cc096df03b4611b1e0f7f9002bac86856d4"},
     .signature_r =
         {"2df3906527ad322000285bccdd11dd09130d633cf43534f5802604639eb847e0"},
     .signature_s =
         {"adaaad19b7c66836ef0f4afeff8ac5e898cd2523246a74a1a291a3a1ff583322"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"f7afb86bb6943f7c0108c31185102a323311011529b95ffc0a9a22b63e310f50a948"
          "13089c2541d4f864ba1e9dd275cf5abfa79d5126e8164f1c1f78fecc0d24808cf519"
          "a6e93648b0fa4da4cbd2888c5e02867653287de8a7cb4ae6a7a5c8dcbef01bf79d31"
          "f22d7d933e5bf25bec1d773f7a5ae67fc5bd58069d3debce16c1"},
     .public_key =
         {"70b4bba10b7bbc6d4175ada8d485f3685b13916d0c992301f47e45b629c63d0e"
          "257a93be31b09ff4cd22e3375e30b5a79f3bf3c74c80dde93e5d65e88c07c1c4"},
     .signature_r =
         {"6e714a737b07a4784d26bde0399d8eee81998a13363785e2e4fb527e6a5c9e4e"},
     .signature_s =
         {"94c0220f0f3fa66ff24f96717f464b66ae3a7b0f228ab6a0b5775038da13768a"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"dfd611caa868f764527c54f144dcabcab1fa7722882bfe293a15b35b0250d3936466"
          "df4eb1f87e053295290ba34390e6efcd64677a8771d48cf8aefb59951d47149c95f9"
          "0e7cfab53b996f53b4a97e6696e6dcb4b0c8282e5405e98fa5da1ad7536a018ccb5b"
          "921873d89f957386e9aabeb8cbdb908d49d4cce97a63268d8863"},
     .public_key =
         {"8b11b48d2397355000a5289d816b9892ae64dffc842abec02a2fb2db2bb34310"
          "fc1a42528a0473cfc2c2e184b8bc5055096350fe1549d24b526d6536681026e8"},
     .signature_r =
         {"61a91dd1c80049e70dc4aea84bda0efc6ec9c7b9dd16ecbccf687244c51184ce"},
     .signature_s =
         {"e381e7b32bab49578c7e7ce7784ce19263e4a7dab4b614df411d20eaebfc391c"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"6707e3bb71ce50247337cba8b70a684fdd1d2c7bb677b999e0766e31f380ae658bba"
          "06094d89a0c344cbc7425a093c1382f1d2d3670ee4292928a472126a9c7e48acbe3f"
          "5fe3176e76e62668b4f8c01fc8194509e4aef12722d626d932e6c8e1972c9d9aeea5"
          "b862ea13121664d900dcaf6d4c8ce5b06c6585af8424b3df5cc1"},
     .public_key =
         {"7bad1b3d8bad4355a44511d2eb50daeae793af99418ada118327359936aa0e1d"
          "e7eff40334b7a5455f6b0d0ecdcdc513702857bb5bbb73c910c86746092bcd7d"},
     .signature_r =
         {"fd961b60b21be32b47abafa77e22197dc99af6825dcca46e0e3b1991a90aa202"},
     .signature_s =
         {"a0477f97b94a1c26a3b2d186791d7fc9dfa8130bbae79c28fa11ec93a3aeac0b"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"e166218ec72b1c41c436305949417c607c02607318fba65659b0c6e484f2ef3a814b"
          "056b1f4ac3d8bfacce79c1d21fe0f9e76714a540dab55c9a22b5d4d2877cdd8f9ef5"
          "a259fe2724b9e4ecf9c20e34f0da8dbec1496f4442010b138e915ea4a71c7eed4b8f"
          "f15679b82d4c45e01b53aeb7b2f07c8baa08e1cb0d95c4f29755"},
     .public_key =
         {"407d92c9b28723602bf09f20f0de002afdf90e22cb709a8d38e3c51e82cba96c"
          "4530659432e1dd74237768133e1f9808e62d0fbe5d1d979d1571baf645dcb84c"},
     .signature_r =
         {"a7dc65293ee3deb0008ae3e2d7ef9e9a4ebb8bf7b10d165f80ab8bed58d6fdef"},
     .signature_s =
         {"3e8300a3ee603a8d8234fe265c628e705015bf1903eb74c943323050626f701f"},
     .hash_function_id = SHA_224,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"bd808ee61aa7f2cd405366f7bed152e137c427123ddebc73264b2df06a780a47ebd2"
          "8f4c5cdab2640be9e7a0d2f75a8782998d73e44ca6b579892590abc70b34e33c8495"
          "e9c4ec7416f3530193f04f7bf9d7b3477af693619141a6a24dfc9ea9f0ee795cca8c"
          "9b418db2716456e3fd5dbee55f22aa8c9986673b1a4b631fdfb7"},
     .public_key =
         {"26aea3dd5c53f984dbdaf415c7f26e1e73048658a548eb3b59dd5f721899919a"
          "dff15f57bd9b08644d49cbb214403647195725cd4d4511bc8a48b0770466ae9f"},
     .signature_r =
         {"726af92afe53e8125b0b9f3659745be401a37ae658b7b1aa88c3cb97e9de22c3"},
     .signature_s =
         {"794484c5837a419efe11a4e4293341a6fa36d21230925a0e5e135887302acca9"},
     .hash_function_id = SHA_224,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"71755d628e025a37c0659b208907d64cf984f6f18b60ba74fa172595ca4a92552bf9"
          "3f37d800b2777fb7f97cd94e256a203b8046c40ae2236fa7ade88e339ce42a6e976d"
          "17575ce4617b017b890ac24cff2a1ea4283c923133ae5eb393400a431ae6ed650e67"
          "c5cf9fb1f7d7e47719d8a3462588bd5980a4325097fdbf12494d"},
     .public_key =
         {"e73418677ce044b331a6d60773cbae199221699d31e1bec4b68b9bc0b87e4cd0"
          "37215db4e3d9161f3351b385a61ddb2fcf1cec469d1659e7574610ed27fe879f"},
     .signature_r =
         {"ac469290a8f61a2a8c6adc7533dd5cfe804e2e7bf101cc74e5f624f301bccd23"},
     .signature_s =
         {"4c328c3bc259316641fff44753743afebe89b8627f904df7245e42adcff2dc76"},
     .hash_function_id = SHA_224,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"d2d44d06dae06355f7d9e09077a742a16755254812b671fd7535653ed5acade929b1"
          "38e72a678b6f9deb5ed407d60b67cf1db10b3bb15b97a1c2946abce915d281c5a1bf"
          "498388bc13c61e735b1800e26919ede5236cfcf3628284120dc03438ffed8cd192d6"
          "51207638e482ca7bb6ff2f6f935462035f7c48328329ea68a8fc"},
     .public_key =
         {"b0892b19c508b3543a5ae864ba9194084c8f7ae544760759550cc160972e87ff"
          "9208e9b0c86ad6bc833e53026f233db9a42298cdb35d906326008377520b7d98"},
     .signature_r =
         {"a62dd0d1518c6b9c60de766b952312a8d8c6eaa36a68196d2a30a46fb17dc067"},
     .signature_s =
         {"b9ded660e978129277f74c1d436003d1e6d556dc8eed9d505bbaf4c67cb13d21"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"0a04ccd0555acac9e47faff6b6dea1f422e4aec83029795d8b9063bbd2e5306e0977"
          "cde1b9d78e005f0e3f3d004e95c87ba5b526f1eb9843e1de8cbf3f2d31b41eabc2ff"
          "dc317840804216a2b6127040336cca086734f8d757362fe8736bf0e7e4fdf4aded8e"
          "9ceb76d20b9829588b4145afdb208c551407e65d7de955619250"},
     .public_key =
         {"8c5c41cb07d828a6a86be4533aef791d3a70a95cb285aa2956b21feeac2f8c49"
          "84101581cad7a48b7d0596df7ffed47085d22e8a4af685cddbeeb32ea69ae190"},
     .signature_r =
         {"9812449df0a51f7a2a8f78aa9a589ca9644dce285f1e69658daaea759fa5bd7e"},
     .signature_s =
         {"beb4c27c748a7944e37afe861576f76b5a749a8ccbbd7dec00838ba250ddfe1a"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"7b11d09b5e7971ac07919f902c59e4490c70d1ecc3f56b625fa836b056187b2a95f7"
          "52e60546c871b509201e9109085c1fd607d677cfc96780f12c3c2640b36d03b72dff"
          "ab156592a462abac041ca7996906baf4d51d55753b3ea3ab985f30fdb698338bb336"
          "644a02203ed839e7a4a7f23c2e04e33a787a92aaba834fb507f1"},
     .public_key =
         {"788d7e54ab03020e4954f41259052ee5af68361492b180da31fbbe68d868aa95"
          "982a3ababa6d351649e56da3faeb7160b9de74e22fe93a06ead1bd9a8dffdf7e"},
     .signature_r =
         {"3ddea06bf8aa4a1b0c68674a2c4796def0bfb52236f4efb3332204a41fd8ea89"},
     .signature_s =
         {"871237039431a41aeefcdd08f67848b2b09067e3a1344c8ed9b372d1b1c754a6"},
     .hash_function_id = SHA_224,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa6"
          "0326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb22"
          "9654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d"
          "6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0"},
     .public_key =
         {"87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555"
          "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9"},
     .signature_r =
         {"d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0"},
     .signature_s =
         {"a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d68387"
          "7f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789c"
          "bf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e"
          "93924fdddd3972af5273198f5efda0746219475017557616170e"},
     .public_key =
         {"5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2"
          "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85"},
     .signature_r =
         {"dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693"},
     .signature_s =
         {"d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (2 - R changed)
    {.data =
         {"df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d74"
          "6429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af8"
          "17317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667"
          "b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de"},
     .public_key =
         {"2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb"
          "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64"},
     .signature_r =
         {"9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8"},
     .signature_s =
         {"9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e"
          "2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922"
          "dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5e"
          "f21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3"},
     .public_key =
         {"e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c"
          "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927"},
     .signature_r =
         {"bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f"},
     .signature_s =
         {"17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c"},
     .hash_function_id = SHA_256,
     .result = VERIFICATION_SUCCESS},
    {.data =
         {"73c5f6a67456ae48209b5f85d1e7de7758bf235300c6ae2bdceb1dcb27a7730f"
          "b68c950b7fcada0ecc4661d3578230f225a875e69aaa17f1e71c6be5c831f226"
          "63bac63d0c7a9635edb0043ff8c6f26470f02a7bc56556f1437f06dfa27b487a"
          "6c4290d8bad38d4879b334e341ba092dde4e4ae694a9c09302e2dbf443581c08"},
     .public_key =
         {"e0fc6a6f50e1c57475673ee54e3a57f9a49f3328e743bf52f335e3eeaa3d2864"
          "7f59d689c91e463607d9194d99faf316e25432870816dde63f5d4b373f12f22a"},
     .signature_r =
         {"1d75830cd36f4c9aa181b2c4221e87f176b7f05b7c87824e82e396c88315c407"},
     .signature_s =
         {"cb2acb01dac96efc53a32d4a0d85d0c2e48955214783ecf50a4f0414a319c05a"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"666036d9b4a2426ed6585a4e0fd931a8761451d29ab04bd7dc6d0c5b9e38e6c2b263"
          "ff6cb837bd04399de3d757c6c7005f6d7a987063cf6d7e8cb38a4bf0d74a282572bd"
          "01d0f41e3fd066e3021575f0fa04f27b700d5b7ddddf50965993c3f9c7118ed78888"
          "da7cb221849b3260592b8e632d7c51e935a0ceae15207bedd548"},
     .public_key =
         {"a849bef575cac3c6920fbce675c3b787136209f855de19ffe2e8d29b31a5ad86"
          "bf5fe4f7858f9b805bd8dcc05ad5e7fb889de2f822f3d8b41694e6c55c16b471"},
     .signature_r =
         {"25acc3aa9d9e84c7abf08f73fa4195acc506491d6fc37cb9074528a7db87b9d6"},
     .signature_s =
         {"9b21d5b5259ed3f2ef07dfec6cc90d3a37855d1ce122a85ba6a333f307d31537"},
     .result = ERROR_NOT_CANONICALIZED}, // (2 - R changed)
    {.data =
         {"7e80436bce57339ce8da1b5660149a20240b146d108deef3ec5da4ae256f8f894edc"
          "bbc57b34ce37089c0daa17f0c46cd82b5a1599314fd79d2fd2f446bd5a25b8e32fcf"
          "05b76d644573a6df4ad1dfea707b479d97237a346f1ec632ea5660efb57e8717a862"
          "8d7f82af50a4e84b11f21bdff6839196a880ae20b2a0918d58cd"},
     .public_key =
         {"3dfb6f40f2471b29b77fdccba72d37c21bba019efa40c1c8f91ec405d7dcc5df"
          "f22f953f1e395a52ead7f3ae3fc47451b438117b1e04d613bc8555b7d6e6d1bb"},
     .signature_r =
         {"548886278e5ec26bed811dbb72db1e154b6f17be70deb1b210107decb1ec2a5a"},
     .signature_s =
         {"e93bfebd2f14f3d827ca32b464be6e69187f5edbd52def4f96599c37d58eee75"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a"
          "649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f22d88c353"
          "965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c438849e2cea2"
          "62a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169"},
     .public_key =
         {"69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214"
          "d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f"},
     .signature_r =
         {"288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790"},
     .signature_s =
         {"247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979"},
     .hash_function_id = SHA_256,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"3fe60dd9ad6caccf5a6f583b3ae65953563446c4510b70da115ffaa0ba04c076115c"
          "7043ab8733403cd69c7d14c212c655c07b43a7c71b9a4cffe22c2684788ec6870dc2"
          "013f269172c822256f9e7cc674791bf2d8486c0f5684283e1649576efc982ede17c7"
          "b74b214754d70402fb4bb45ad086cf2cf76b3d63f7fce39ac970"},
     .public_key =
         {"bf02cbcf6d8cc26e91766d8af0b164fc5968535e84c158eb3bc4e2d79c3cc682"
          "069ba6cb06b49d60812066afa16ecf7b51352f2c03bd93ec220822b1f3dfba03"},
     .signature_r =
         {"f5acb06c59c2b4927fb852faa07faf4b1852bbb5d06840935e849c4d293d1bad"},
     .signature_s =
         {"049dab79c89cc02f1484c437f523e080a75f134917fda752f2d5ca397addfe5d"},
     .hash_function_id = SHA_256,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"983a71b9994d95e876d84d28946a041f8f0a3f544cfcc055496580f1dfd4e312a2ad"
          "418fe69dbc61db230cc0c0ed97e360abab7d6ff4b81ee970a7e97466acfd9644f828"
          "ffec538abc383d0e92326d1c88c55e1f46a668a039beaa1be631a89129938c00a81a"
          "3ae46d4aecbf9707f764dbaccea3ef7665e4c4307fa0b0a3075c"},
     .public_key =
         {"224a4d65b958f6d6afb2904863efd2a734b31798884801fcab5a590f4d6da9de"
          "178d51fddada62806f097aa615d33b8f2404e6b1479f5fd4859d595734d6d2b9"},
     .signature_r =
         {"87b93ee2fecfda54deb8dff8e426f3c72c8864991f8ec2b3205bb3b416de93d2"},
     .signature_s =
         {"4044a24df85be0cc76f21a4430b75b8e77b932a87f51e4eccbc45c263ebf8f66"},
     .hash_function_id = SHA_256,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"4a8c071ac4fd0d52faa407b0fe5dab759f7394a5832127f2a3498f34aac287339e04"
          "3b4ffa79528faf199dc917f7b066ad65505dab0e11e6948515052ce20cfdb892ffb8"
          "aa9bf3f1aa5be30a5bbe85823bddf70b39fd7ebd4a93a2f75472c1d4f606247a9821"
          "f1a8c45a6cb80545de2e0c6c0174e2392088c754e9c8443eb5af"},
     .public_key =
         {"43691c7795a57ead8c5c68536fe934538d46f12889680a9cb6d055a066228369"
          "f8790110b3c3b281aa1eae037d4f1234aff587d903d93ba3af225c27ddc9ccac"},
     .signature_r =
         {"8acd62e8c262fa50dd9840480969f4ef70f218ebf8ef9584f199031132c6b1ce"},
     .signature_s =
         {"cfca7ed3d4347fb2a29e526b43c348ae1ce6c60d44f3191b6d8ea3a2d9c92154"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"0a3a12c3084c865daf1d302c78215d39bfe0b8bf28272b3c0b74beb4b7409db07182"
          "39de700785581514321c6440a4bbaea4c76fa47401e151e68cb6c29017f0bce46312"
          "90af5ea5e2bf3ed742ae110b04ade83a5dbd7358f29a85938e23d87ac8233072b79c"
          "94670ff0959f9c7f4517862ff829452096c78f5f2e9a7e4e9216"},
     .public_key =
         {"9157dbfcf8cf385f5bb1568ad5c6e2a8652ba6dfc63bc1753edf5268cb7eb596"
          "972570f4313d47fc96f7c02d5594d77d46f91e949808825b3d31f029e8296405"},
     .signature_r =
         {"dfaea6f297fa320b707866125c2a7d5d515b51a503bee817de9faa343cc48eeb"},
     .signature_s =
         {"8f780ad713f9c3e5a4f7fa4c519833dfefc6a7432389b1e4af463961f09764f2"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"785d07a3c54f63dca11f5d1a5f496ee2c2f9288e55007e666c78b007d95cc28581dc"
          "e51f490b30fa73dc9e2d45d075d7e3a95fb8a9e1465ad191904124160b7c60fa720e"
          "f4ef1c5d2998f40570ae2a870ef3e894c2bc617d8a1dc85c3c55774928c38789b4e6"
          "61349d3f84d2441a3b856a76949b9f1f80bc161648a1cad5588e"},
     .public_key =
         {"072b10c081a4c1713a294f248aef850e297991aca47fa96a7470abe3b8acfdda"
          "9581145cca04a0fb94cedce752c8f0370861916d2a94e7c647c5373ce6a4c8f5"},
     .signature_r =
         {"09f5483eccec80f9d104815a1be9cc1a8e5b12b6eb482a65c6907b7480cf4f19"},
     .signature_s =
         {"a4f90e560c5e4eb8696cb276e5165b6a9d486345dedfb094a76e8442d026378d"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"76f987ec5448dd72219bd30bf6b66b0775c80b394851a43ff1f537f140a6e7229ef8"
          "cd72ad58b1d2d20298539d6347dd5598812bc65323aceaf05228f738b5ad3e8d9fe4"
          "100fd767c2f098c77cb99c2992843ba3eed91d32444f3b6db6cd212dd4e5609548f4"
          "bb62812a920f6e2bf1581be1ebeebdd06ec4e971862cc42055ca"},
     .public_key =
         {"09308ea5bfad6e5adf408634b3d5ce9240d35442f7fe116452aaec0d25be8c24"
          "f40c93e023ef494b1c3079b2d10ef67f3170740495ce2cc57f8ee4b0618b8ee5"},
     .signature_r =
         {"5cc8aa7c35743ec0c23dde88dabd5e4fcd0192d2116f6926fef788cddb754e73"},
     .signature_s =
         {"9c9c045ebaa1b828c32f82ace0d18daebf5e156eb7cbfdc1eff4399a8a900ae7"},
     .hash_function_id = SHA_256,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"60cd64b2cd2be6c33859b94875120361a24085f3765cb8b2bf11e026fa9d8855dbe4"
          "35acf7882e84f3c7857f96e2baab4d9afe4588e4a82e17a78827bfdb5ddbd1c211fb"
          "c2e6d884cddd7cb9d90d5bf4a7311b83f352508033812c776a0e00c003c7e0d628e5"
          "0736c7512df0acfa9f2320bd102229f46495ae6d0857cc452a84"},
     .public_key =
         {"2d98ea01f754d34bbc3003df5050200abf445ec728556d7ed7d5c54c55552b6d"
          "9b52672742d637a32add056dfd6d8792f2a33c2e69dafabea09b960bc61e230a"},
     .signature_r =
         {"06108e525f845d0155bf60193222b3219c98e3d49424c2fb2a0987f825c17959"},
     .signature_s =
         {"62b5cdd591e5b507e560167ba8f6f7cda74673eb315680cb89ccbc4eec477dce"},
     .hash_function_id = SHA_256,
     .result = VERIFICATION_SUCCESS},
    {.data =
         {"fe9838f007bdc6afcd626974fcc6833f06b6fd970427b962d75c2aeadbef386bec8d"
          "018106197fe2547d2af02e7a7949965d5fbc4c5db909a95b9858426a33c080b0b25d"
          "ae8b56c5cbc6c4eec3dbd81635c79457eaef4fab39e662a1d05b2481eda8c1074ae2"
          "d1704c8a3f769686a1f965ef3c87602efc288c7f9ff8cd5e22a4"},
     .public_key =
         {"40ded13dbbe72c629c38f07f7f95cf75a50e2a524897604c84fafde5e4cafb9f"
          "a17202e92d7d6a37c438779349fd79567d75a40ef22b7d09ca21ccf4aec9a66c"},
     .signature_r =
         {"be34730c31730b4e412e6c52c23edbd36583ace2102b39afa11d24b6848cb77f"},
     .signature_s =
         {"03655202d5fd8c9e3ae971b6f080640c406112fd95e7015874e9b6ee77752b10"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"b69043b9b331da392b5dd689142dfc72324265da08f14abcedf03ad8263e6bdccbc7"
          "5098a2700bbba1979de84c8f12891aa0d000f8a1abad7dde4981533f21da59cc80d9"
          "cf94517f3b61d1a7d9eecb2fcf052e1fc9e7188c031b86305e4a436a37948071f046"
          "e306befb8511dc03a53dc8769a90a86e9b4fdbf05dcdfa35ab73"},
     .public_key =
         {"1f80e19ffeb51dd74f1c397ac3dfd3415ab16ebd0847ed119e6c3b15a1a884b8"
          "9b395787371dbfb55d1347d7bed1c261d2908121fb78de1d1bf2d00666a62aed"},
     .signature_r =
         {"249ca2c3eb6e04ac57334c2f75dc5e658bbb485bf187100774f5099dd13ef707"},
     .signature_s =
         {"97363a05202b602d13166346694e38135bbce025be94950e9233f4c8013bf5bf"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"d2fcaaede8b879c064b0aa46e68efc278a469b80a7f7e1939ec2ebc96c76206f2339"
          "5967279c181fea157ebb79dfadc68e31345f07f13305c80de0d85e4330d3a45f957c"
          "5c2526b945838ce5a9c2844b6b2a665c0f70b748b1213a8cf20ba5dbdf8cab231f43"
          "3da522104a5cd027d3e36bb373c4ed404d9af0cbec6f85ec2193"},
     .public_key =
         {"ce4dcfa7384c83443ace0fb82c4ac1adfa100a9b2c7bf09f093f8b6d084e50c2"
          "d98ae7b91abee648d0bfde192703741ac21daad7262af418b50e406d825eb0d6"},
     .signature_r =
         {"597e1e04d93a6b444ccc447a48651f17657ff43fb65fe94461d2bf816b01af40"},
     .signature_s =
         {"359fe3817963548e676d6da34c2d0866aa42499237b682002889eaf8893814d2"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_SUCCESS},
    {.data =
         {"06cd86481865181cef7acdc3202824970ec2d97662b519c4b588dc9e51617c068282"
          "b1a11a15bf7efc4858a2f37a3d74b05fb5790eb68338c8009b4da9b4270514d387a2"
          "e016a99ee109841e884a7909504ef31a5454e214663f830f23a5a76f91402fca5f5d"
          "61699fa874597bdbfb1ecff8f07ddbd07ef61e97d0d5262ef314"},
     .public_key =
         {"1b677f535ac69d1acd4592c0d12fac13c9131e5a6f8ab4f9d0afdcb3a3f327e0"
          "5dca2c73ec89e58ef8267cba2bb5eb0f551f412f9dc087c1a6944f0ce475277a"},
     .signature_r =
         {"df0b0cd76d2555d4c38b3d70bfdf964884d0beeb9f74385f0893e87d20c9642d"},
     .signature_s =
         {"128299aabf1f5496112be1fe04365f5f8215b08a040abdfeca4626f4d15c005b"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"59ad297397f3503604a4a2d098a4f00a368ad95c6101b3d38f9d49d908776c5a6c86"
          "54b006adb7939ffb6c30afa325b54185d82c3cc0d836850dce54d3408b257c3a961d"
          "11fafe2b74ba8bddfc1102fa656d1028baf94c38340c26a11e992aab71ce3732271b"
          "767358671b25225926f3a4b9ec5f82c059f0c7d1446d5d9e4251"},
     .public_key =
         {"7ffc2853f3e17887dda13b0eb43f183ce50a5ac0f8bba75fb1921172484f9b94"
          "4cc523d14192f80bd5b27d30b3b41e064da87bfbae15572dd382b9a176c123a2"},
     .signature_r =
         {"3156176d52eb26f9391229de4251993a41b8172f78970bb70e32a245be4bb653"},
     .signature_s =
         {"62827a29e12d2f29b00fb2d02dd5f2d5412e17a4455f4431a5c996881fdfc0ee"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"8215daca87e689a20392646a6511bb7b5a82d2d995ca9de89bd9d9c0b11464b7cb1e"
          "4e9a31e3e01ad8c2cd613d5a2cb44a2a8df6899fce4c282dea1e41af0df6c36be1f3"
          "20036567f8d0d32aaa79c95fe53b16668f7e1a9e5d7d039ea260fd03711b7d1c1773"
          "55fc52244d49ca5b238556a5541349014683cb7da326f443b752"},
     .public_key =
         {"5569f76dc94243cde819fb6fc85144ec67e2b5d49539f62e24d406d1b68f0058"
          "1208c38dbe25870deab53c486f793a1e250c9d1b8e7c147ea68b71196c440730"},
     .signature_r =
         {"706f2ba4025e7c06b66d6369a3f93b2fec46c51eceff42a158f7431919506cfb"},
     .signature_s =
         {"b4e75ac34a96393237fc4337789e37168d79382705b248051c9c72bcbac5f516"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED}, // (2 - R changed)
    {.data =
         {"a996b1fb800f692517a2eb80e837233193dd3e82484d3f49bd19ee0db8f7b440876b"
          "07e384c90aa8b9f7b6603ca0b5a4e06c1da0edb974a2fb9b6e7c720ddf3e5c0e314c"
          "2d189402903c08c0836776c361a284db887ebcc33e615de9720b01dadade585eef68"
          "7b3346468bdafb490e56d657a9e7d44d92014069005a36c1cf63"},
     .public_key =
         {"e4b470c65b2c04db060d7105ec6911589863d3c7f7ce48726ba3f369ea3467e8"
          "44c38d3ae098de05f5915a5868c17fee296a6e150beb1f000df5f3bec8fc4532"},
     .signature_r =
         {"c9c347ee5717e4c759ddaf09e86f4e1db2c8658593177cfda4e6514b5e3ecb87"},
     .signature_s =
         {"baae01e9e44a7b04d69c8eaaed77c9e3a36ce8962f95cc50a0db146b4e49eb40"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"1a6e49a377a08e992353d6acc557b687b1b69a41d83d43a75fadb97b8c928cfebade"
          "baaf99ea7fb13148807f56ea17384a7912e578e62b1b009fefb2aafca5ac85539433"
          "619b286f10643a56f8dfa47ba4d01c02510deaec18029ea6b9682022b139dcb70814"
          "164c4c90ec717ad9d925485398531cdd5992a2524498b337f97d"},
     .public_key =
         {"96050c5fa2ddd1b2e5451d89ee74a0b7b54347364ddc0231715a6ef1146fe8dc"
          "e0888a9e78aeea87f6e1e9002b2651169f36c4ee53013cfc8c9912b7fd504858"},
     .signature_r =
         {"2353d6cd3c21b8ea7dbc1cd940519812dbe365a3b15cd6aebba9d11cf269867a"},
     .signature_s =
         {"85f560273cd9e82e6801e4cb1c8cd29cdac34a020da211d77453756b604b8fa7"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"3e14f737c913931bc82764ebc440b12e3ce1ffe0f858c7b8f1cbd30fbbb1644fa59b"
          "e1d2cca5f64a6d7dc5ed5c4420f39227516ae8eb3019ef86274d0e4d06cde7bf5e5c"
          "413243dfc421d9f141762109810e6b6a451eeb4bd8d4be1ff111426d7e44d0a916b4"
          "fe3db3594d8dd01ae90feecf8f1e230b574180cd0b8d43a3d33b"},
     .public_key =
         {"0c07bb79f44012299fbfd5a0f31397aaf7d757f8a38437407c1b09271c6551a0"
          "84fe7846d5d403dc92c0091fbd39f3c5cbca3f94c10b5cae44e2e96562131b13"},
     .signature_r =
         {"49e9425f82d0a8c503009cead24e12adc9d48a08594094ca4f6d13ad1e3c571d"},
     .signature_s =
         {"1f1b70aaa30a8ff639aa0935944e9b88326a213ab8fce5194c1a9dec070eb433"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"4000106127a72746db77957cbc6bfd84ae3d1d63b8190087637e93689841331e2adc"
          "1930d6df4302935f4520bbee513505cdcfca99ebc6f83af7b23b0f2e7f7defba6140"
          "22ceeae9c6886e8b13f7ea253a307ac301f3536720cbe3de82ba3e98310361b61801"
          "a8304ffc91ff774948e33176ddcddf1b76437b3f02c910578d46"},
     .public_key =
         {"71db1de1a1f38f356c91feaff5cfe395d1a5b9d23cf6aa19f38ae0bcc90a486d"
          "ecdd6ffb174a50f1cc792985c2f9608c399c98b8a64a69d2b5b7cdd9241f67e2"},
     .signature_r =
         {"b0443b33a6f249470d2f943675009d21b9ccbead1525ae57815df86bb20470bf"},
     .signature_s =
         {"316dbee27d998e09128539c269e297ac8f34b9ef8249a0619168c3495c5c1198"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"b42e547d0e7ddd5e1069bb2d158a5b4d5d9c4310942a1bfd09490311a6e684bd3c29"
          "b0dcef86a9788b4b26fed7863f3d5e5439796b5b5ffe7aa2545d0f518ad020689ca2"
          "1230f3a59e7f8cca465fe21df511e78d215fa805f5f0f88938e9d198515e6b9c8199"
          "30755c6c6aea5114cd2904607243051c09dd7a147756cbc204a5"},
     .public_key =
         {"8219b225aa15472262c648cac8de9aad4173d17a231ba24352a5a1c4eea70fad"
          "0fee2b08ad39fbf0db0016ef2896ca99adc07efc8c415f640f3720498be26037"},
     .signature_r =
         {"134fb689101aaad3954de2819d9fbd12072fe2bc36f496bbf0d13fa72114ab96"},
     .signature_s =
         {"e65c232bd915b59e087e7fd5ec90bf636cfa80526345c79a0adfd75003045d6f"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"aa563223a7d5201febdf13cab80a03dce6077c26e751bc98a941196a28848abc495e"
          "0324013c9a2094fb15dc65d100c3e8a136a52c1780b395f42588900b641b6d436143"
          "2e2173195a2f60189f3fcc85f4e9659cae52576f20d1852d43c2b400deea3144c8e8"
          "70e1906d677425d8c85037c7a42a9d249b2da4b516e04476bd45"},
     .public_key =
         {"c934195de33b60cf00461fc3c45dad068e9f5f7af5c7fa78591e95aeb04e2617"
          "b588dd5f9965fdaa523b475c2812c251bc6973e2df21d9beaace976abf5728cb"},
     .signature_r =
         {"71f302440eb4ed2a939b69e33e905e6fdc545c743458d38f7e1a1d456e35f389"},
     .signature_s =
         {"54eaa0eb9cd7503b19a9658f0a04955d9f0ab20ebc8a0877e33c89ee88ad068f"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (4 - Q changed)
    {.data =
         {"98e4babf890f52e5a04bd2a7d79bf0ae9a71967847347d87f29fb3997454c73c7979"
          "d15b5c4f4205ec3de7835d1885fb7abcf8dcde94baf08b1d691a0c74845317286540"
          "e8c9d378fefaa4762c302492f51023c0d7adbb1cc90b7b0335f11203664e71fea621"
          "bc2f59d2dbd0ee76d6597ec75510de59b6d25fa6750a71c59435"},
     .public_key =
         {"9e1adcd48e2e3f0e4c213501808228e587c40558f52bb54ddbb6102d4048ea92"
          "34eff98704790938e7e0bdf87ae39807a6b77dfdc9ecdfe6dd0f241abae1aeb2"},
     .signature_r =
         {"ce4f0d7480522c8dd1b02dd0eb382f22406642f038c1ede9411883d72b3e7ed0"},
     .signature_s =
         {"8546e1ee3b77f9927cdaccbc2f1cf19d6b5576b0f738bb1b86a0c66b39ca56fb"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"bb6b03ad60d6ddbf0c4d17246206e61c886f916d252bb4608149da49cef903348408"
          "0e861f91bb2400baa0cd6c5d90c2f275e2fabc12d83847f7a1c3ff0eb40c8a3dd83d"
          "07d194ba3797d27238415a2f358d7292a1991af687bcb977486980f9138b31403214"
          "85638ac7bd22ecda00ffe5009b83b90397eff24ecf22c5495d67"},
     .public_key =
         {"93edbecb0b019c2cc03060f54cb4904b920fdb34eb83badd752be9443036ae13"
          "b494e9295e080a9080fe7e73249b3a5904aa84e1c028121eecd3e2cf1a55f598"},
     .signature_r =
         {"eec2986d47b71995892b0915d3d5becc4dcb2ab55206d772e0189541b2184ddf"},
     .signature_s =
         {"8a6c1edeb6452627ad27c8319599c54ac44cdd831ea66f13f49d90affe6ad45b"},
     .hash_function_id = SHA_384,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"33a5d489f671f396c776bc1acf193bc9a74306f4692dd8e05bcdfe28fdefbd5c09b8"
          "31c204a1dec81d8e3541f324f7b474d692789013bb1eca066f82fbf3f1cf3ba64e9d"
          "8963e9ecc180b9251919e2e8a1ab05847a0d76ff67a47c00e170e38e5b319a56f59c"
          "c51038f90961ea27a9a7eb292a0a1aa2f4972568669246907a35"},
     .public_key =
         {"3205bae876f9bd50b0713959e72457165e826cbbe3895d67320909daa48b0ebc"
          "d1592562273e5e0f57bbfb92cedd9af7f133255684ee050af9b6f02019bbcafa"},
     .signature_r =
         {"0124f3f1c61ec458561a4eaa6c155bd29e59703d14556324924683db3a4cf43b"},
     .signature_s =
         {"688a5c5fc0c7ba92210c50cce5b512a468a880e05acc21ca56571d89f45f603a"},
     .hash_function_id = SHA_384,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"273b063224ab48a1bf6c7efc93429d1f89de48fc4a4fa3ffe7a49ebba1a58ff5d208"
          "a9e4bff27b418252526243ba042d1605b6df3c2ec916ceef027853a41137f7bfb6fc"
          "63844de95f58e82b9ad2565f1367d2c69bd29100f6db21a8ab7ab58affd1661add03"
          "22bd915721378df9fa233ef0b7e0a0a85be31689e21891ec8977"},
     .public_key =
         {"484e31e69ef70bb8527853c22c6b6b4cd2a51311dde66c7b63f097dbb6ab27bf"
          "e1ff8177f4061d4fbbacbbc70519f0fc8c8b6053d72af0fe4f048d615004f74e"},
     .signature_r =
         {"91a303d8fe3ab4176070f6406267f6b79bfe5eb5f62ae6aeb374d90667858518"},
     .signature_s =
         {"e152119cefa26826ea07ec40a428869132d70812c5578c5a260e48d6800e046a"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (1 - Message changed)
    {.data =
         {"d64ea1a768b0de29ab018ae93baa645d078c70a2f7aa4acd4ae7526538ebd5f697a1"
          "1927cfd0ddc9187c095f14ad30544cb63ede9353af8b23c18ce22843881fe2d7bde7"
          "48fc69085921677858d87d2dc3e244f6c7e2c2b2bd791f450dfdd4ff0ddd35ab2ada"
          "4f1b90ab16ef2bf63b3fbe88ce8a5d5bb85430740d3744849c13"},
     .public_key =
         {"8b75fc0129c9a78f8395c63ae9694b05cd6950665cf5da7d66118de451422624"
          "b394171981d4896d6e1b4ef2336d9befe7d27e1eb87f1c14b8ddda622af379dc"},
     .signature_r =
         {"17e298e67ad2af76f6892fdcead00a88256573868f79dc74431b55103058f0b0"},
     .signature_s =
         {"881328cd91e43d30133f6e471e0b9b04353b17893fb7614fd7333d812a3df6b4"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"1db85445c9d8d1478a97dd9d6ffbf11ebcd2114d2ed4e8b6811171d947e7d4daedea"
          "35af6177debe2ef6d93f94ff9d770b45d458e91deb4eef59856425d7b00291aff9b6"
          "c9fa02375ec1a06f71f7548721790023301cf6ac7fee1d451228106ef4472681e652"
          "c8cd59b15d6d16f1e13440d888e265817cb4a654f7246e0980df"},
     .public_key =
         {"76e51086e078b2b116fd1e9c6fa3d53f675ae40252fb9f0cc62817bd9ce8831d"
          "ca7e609a0b1d14b7c9249b53da0b2050450e2a25cb6c8f81c5311974a7efb576"},
     .signature_r =
         {"23b653faaa7d4552388771931803ce939dd5ee62d3fa72b019be1b2272c85592"},
     .signature_s =
         {"a03c6f5c54a10861d6b8922821708e9306fd6d5d10d566845a106539cbf4fadd"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"918d9f420e927b3e0a55d276b8b40d8a2c5df748727ff72a438c7e6593f542274050"
          "dce727980d3ef90c8aa5c13d53f1e8d631ebb650dee11b94902bbd7c92b8186af903"
          "9c56c43f3110697792c8cd1614166f06d09cdb58dab168cc3680a8473b1a623bf85d"
          "ba855eace579d9410d2c4ca5ede6dc1e3db81e233c34ae922f49"},
     .public_key =
         {"bc7c8e09bd093468f706740a4130c544374fdc924a535ef02e9d3be6c6d3bbfa"
          "af3f813ae6646f5b6dbfb0f261fd42537705c800bb1647386343428a9f2e10fc"},
     .signature_r =
         {"6bd7ce95af25abfbf14aef4b17392f1da877ab562eca38d785fe39682e9c9324"},
     .signature_s =
         {"6688bea20c87bab34d420642da9bdd4c69456bdec50835887367bb4fb7cd8650"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"6e2932153301a4eef680e6428929adae988c108d668a31ff55d0489947d75ff81a46"
          "bf89e84d6401f023be6e87688fbcd784d785ca846735524acb52d00452c84040a479"
          "e7cc330936441d93bbe722a9432a6e1db112b5c9403b10272cb1347fd619d463f7a9"
          "d223ad76fde06d8a6883500fb843235abff98e241bdfb5538c3e"},
     .public_key =
         {"9cb0cf69303dafc761d4e4687b4ecf039e6d34ab964af80810d8d558a4a8d6f7"
          "2d51233a1788920a86ee08a1962c79efa317fb7879e297dad2146db995fa1c78"},
     .signature_r =
         {"4b9f91e4285287261a1d1c923cf619cd52c175cfe7f1be60a5258c610348ba3d"},
     .signature_s =
         {"28c45f901d71c41b298638ec0d6a85d7fcb0c33bbfec5a9c810846b639289a84"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_SUCCESS},
    {.data =
         {"2f48ec387f181035b350772e27f478ae6ec7487923692fae217e0f8636acd062a6ac"
          "39f7435f27a0ebcfd8187a91ef00fb68d106b8da4a1dedc5a40a4fae709e92b00fcc"
          "218de76417d75185e59dff76ec1543fb429d87c2ca8134ff5ae9b45456cad93fc672"
          "23c68293231395287dc0b756355660721a1f5df83bf5bcb8456e"},
     .public_key =
         {"e31096c2d512fbf84f81e9bdb16f33121702897605b43a3db546f8fb695b5f6f"
          "6fbec6a04a8c59d61c900a851d8bf8522187d3ec2637b10fa8f377689e086bba"},
     .signature_r =
         {"1b244c21c08c0c0a10477fb7a21382d405b95c755088292859ca0e71bab68361"},
     .signature_s =
         {"852f4cbfd346e90f404e1dd5c4b2c1debca3ea1abefe8400685d703aea6c5c7f"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (4 - Q changed)
    {.data =
         {"fd2e5de421ee46c9fe6290a33f95b394bd5b7762f23178f7f6834f1f056fa9a88314"
          "46403c098ff4dd764173f974be4c89d376119613a4a1890f6fc2ddff862bda292dd4"
          "9f5410d9b1cfe1d97ef4582b6152494372fc083885f540c01f86d780e6f3e75a954a"
          "f2190fdae9604e3f8ab32ab0292dc0d790bd2627e37b4b4885df"},
     .public_key =
         {"633c2ee5630b62c9ce839efd4d485a6d35e8b9430d264ffe501d28dbace79123"
          "4b668a1a6d1a25b089f75c2bd8d8c6a9a14fe7b729f45a82565da2e866e2c490"},
     .signature_r =
         {"bf2111c93ec055a7eda90c106fce494fd866045634fd2aa28d6e018f9106994e"},
     .signature_s =
         {"86b0341208a0aa55edecfd272f49cb34408ce54b7febc1d0a1c2ce77ab6988f8"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"4bc2d9a898395b12701635f1048fbfd263ec115e4150532b034d59e625238f4ed326"
          "19744c612e35ac5a23bee8d5f5651641a492217d305e5051321c273647f14bc7c4af"
          "ab518554e01c82d6fc1694c8bdbeb326bb607bcaf5436303bc09f64c02c6ec50de40"
          "9a484f5237f7d34e2651ada7ec429ca3b99dd87c6015d2f4b342"},
     .public_key =
         {"f78dce40d1cb8c4af2749bf22c6f8a9a470b1e41112796215dd017e57df1b38a"
          "61b29b0bc03dff7fa00613b4de1e2317cfbf2badd50dee3376c032a887c5b865"},
     .signature_r =
         {"4a96169a5dea36a2594011537ee0dc19e8f9f74e82c07434079447155a830152"},
     .signature_s =
         {"a204eaa4e97d7553a1521d9f6baadc0b6d6183ba0f385d8593d6ca83607c4d82"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (2 - R changed)
    {.data =
         {"d3356a683417508a9b913643e6ceac1281ef583f428968f9d2b6540a189d7041c477"
          "da8d207d0529720f70dab6b0da8c2168837476c1c6b63b517ed3cad48ae331cf716e"
          "cf47a0f7d00b57073ac6a4749716d49d80c4d46261d38e2e34b4f43e0f20b280842f"
          "6e3ea34fefdddfb9fa2a040ffe915e8784cfdb29b3364a34ca62"},
     .public_key =
         {"3fcc3b3e1b103fe435ac214c756bdaad309389e1c803e6d84bbbc27039fcf900"
          "7f09edd1ec87a6d36dc81c1528d52a62776e666c274415a9f441d6a8df6b9237"},
     .signature_r =
         {"1cac13f277354456ae67ab09b09e07eb1af2a2bf45108da70f5c8c6a4cbcd538"},
     .signature_s =
         {"5d83752e540525602ba7e6fee4d4263f3eda59e67df20aac79ca67e8899fed0d"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_FAILED}, // (3 - S changed)
    {.data =
         {"d7f5da9f4cf9299b7f86c52b88364ce28fe9ada55dd551a1018790f9e1205e2405ac"
          "62429d65093f74ec35a16d9f195c993cd4eb8dc0aa0dabb70a503321d8a9649160d6"
          "b3d0a0854bb68c4c39693f592ef5dd478aa2432d0865d87d48b3aea9c7d7d114165c"
          "9200e4e8d7bd02a7895ec4418e6f2fed6b244bf66209039e98a9"},
     .public_key =
         {"5ec702d43a67ada86efbfc136cf16d96078906954a3f1f9e440674cd907e4676"
          "05a62044fed8470dd4fca38d89d583ce36d50d28b66ab0b51922b21da92c56d9"},
     .signature_r =
         {"75f3037298f1457dba55743999976a1c2636b2b8ab2ed3df4736a6d2934acc83"},
     .signature_s =
         {"19d43ad168dda1bb8ac423f8f08876515234b3d841e57faef1b5ab27359b27ef"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"68f4b444e1cc2025e8ff55e8046ead735e6e317082edf7ce65e83573501cb92c408c"
          "1c1c6c4fcca6b96ad34224f17b20be471cc9f4f97f0a5b7bfae9558bdb2ecb6e452b"
          "b743603724273d9e8d2ca22afdda35c8a371b28153d772303e4a25dc4f28e9a6dc96"
          "35331450f5af290dfa3431c3c08b91d5c97284361c03ec78f1bc"},
     .public_key =
         {"f63afe99e1b5fc652782f86b59926af22e6072be93390fe41f541204f9c935d1"
          "f6e19ce5935e336183c21becf66596b8f559d2d02ee282aa87a7d6f936f7260c"},
     .signature_r =
         {"cef4831e4515c77ca062282614b54a11b7dc4057e6997685c2fbfa95b392bf72"},
     .signature_s =
         {"f20dc01bf38e1344ba675a22239d9893b3a3e33d9a403329a3d21650e9125b75"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED},
    {.data =
         {"e75be05be0aaf70719b488b89aaae9008707ca528994461db7130c4368575a024bf0"
          "981c305d61265e8b97599ec35c03badd1256b80d6bf70547ad6089b983e3bcc34818"
          "28f3259e43e655e177fc423fd7e066bd3ed68d81df84f773c0f9e5f8bf4469960b8b"
          "4d7b2a372fd0edd3521f6be670908f2d90a343f416358ea70e7e"},
     .public_key =
         {"6d11b09d2767cf8d275faee746c203486259f66dd2bfa3a65c39371a66b23385"
          "4eb05c73e05261e979182833f20311e5366f72f4b949665ff294f959375534c6"},
     .signature_r =
         {"15a697cdb614e11c0810e1e764cd501fcabc70874c957587bc4883d9438e177f"},
     .signature_s =
         {"7bf6244f92bc768063cecb5336c8eaacd23db930b28703560f241c7d93950dfd"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_FAILED}, // (2 - R changed)
    {.data =
         {"0dc4a3eab66bd2e703a8fff566c34d466f9823ae42bd2104f61a6b051c0b017833fc"
          "ef4d609d137ad97c209c80eebe252857aa7fafc35f16000a2bd4b4be0fa83b6e229e"
          "ddfd180101f1f40d0453148053d8306833df64d59599b90194b55541d7f22dd589da"
          "9f7be519cbbb9db416c71bfe40ec090b5b7a600eec29bfd47306"},
     .public_key =
         {"f3899caba038efb534c4cea0bd276814ffd80194473c903b81af11c8c05cb6e6"
          "6ea6b17402fcf2e8e737d11ffc7c2ed3b2d0bc3b8f271a381f4294cff62682c3"},
     .signature_r =
         {"57b99380452e1d37b133c49b9ba493dee8630940477ca3351a43d90b99871e6a"},
     .signature_s =
         {"df599c3a37105af3ecc159b3b685ccb3e151b7d5cf2d97147974ae71f466b615"},
     .hash_function_id = SHA_512,
     .result = ERROR_NOT_CANONICALIZED}, // (3 - S changed)
    {.data =
         {"d55e5e124a7217879ca986f285e22ac51940b35959bbf5543104b5547356fd1a0ec3"
          "7c0a23209004a2ec5bcaf3335bc45e4dc990eacd29b2d9b5cf349c7ba67711356299"
          "bceab6f048df761c65f2988803133d6723a2820fefb2654cc7c5f032f833ba78a34d"
          "2878c6b0ba654ebe26b110c935abb56024bd5d0f09b367724c07"},
     .public_key =
         {"1fd6f4b98d0755291e7a230e9f81ecf909e6350aadb08e42a3262ff19200fbd2"
          "5578fef79bc477acfb8ed0dc10c4f5809c14dc5492405b3792a7940650b305d7"},
     .signature_r =
         {"97a99e96e407b3ada2c2dcf9ceeeb984d9a4d0aa66ddf0a74ca23cabfb1566cc"},
     .signature_s =
         {"0ecac315dc199cfea3c15348c130924a1f787019fe4cd3ae47ca8b111268754a"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_FAILED}, // (1 - Message changed)
    {.data =
         {"7753c03b4202cb38bc0190a9f931eb31858d705d92d650320ff449fc99167fb3770b"
          "764c8988f6b34ac5a3d507a10e0aff7f88293f6a22c7ed8a24248a52dc125e416e15"
          "8833fc38af29199f8ca4931068d4ccaa87e299e95642068f68c208cb782df13908f9"
          "50564743ed1692502bafafaff169dc8fe674fb5e4f3ffd578c35"},
     .public_key =
         {"2dcbd8790cee552e9f18f2b3149a2252dcd58b99ca7dc9680b92c8c43aa33874"
          "5dbc8bb8813c8e019d80e19acdb0792f537980fecde93db621aaf1f6d0e6ee34"},
     .signature_r =
         {"2bdbd8b0d759595662cc10b10236136ef6ce429641f68cf6480f472fcc77bc9f"},
     .signature_s =
         {"7e7df0c8b86f7db06caf1610166f7b9c4c75447f991d5aaf4dea720c25985c8c"},
     .hash_function_id = SHA_512,
     .result = VERIFICATION_SUCCESS},
};
