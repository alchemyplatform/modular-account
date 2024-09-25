// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {ILightAccount} from "./ILightAccount.sol";
import {ILightAccountFactory} from "./ILightAccountFactory.sol";

import {BenchmarkBase} from "../BenchmarkBase.sol";

contract LightAccountGasTest is BenchmarkBase("LightAccount") {
    address internal constant _LIGHT_ACCOUNT_FACTORY = 0x0000000000400CdFef5E2714E63d8040b700BC24;

    bytes internal constant _LIGHT_ACCOUNT_FACTORY_BYTECODE =
        hex"60806040818152600480361015610021575b505050361561001f57600080fd5b005b600092833560e01c908163290ab98414610b21575080635fbfb9cf14610967578063715018a61461090857806379ba5097146108285780638cb84e181461071e5780638da5cb5b146106cd57806394430fa51461065e57838163bb9fe6bf1461059e57508063c23a5cea146104a4578063d9caed12146102b0578063e30c397814610259578063f2fde38b146101ac5763fbb1c3d403610011578183927ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101a85781359163ffffffff83168093036101a3576100ff610c5e565b73ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da0321692833b1561019f5760248592845195869384927f0396cb600000000000000000000000000000000000000000000000000000000084528301528235905af190811561019657506101835750f35b61018c90610bb2565b6101935780f35b80fd5b513d84823e3d90fd5b8480fd5b505050fd5b5050fd5b83346101935760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc360112610193576101e4610b8f565b6101ec610c5e565b73ffffffffffffffffffffffffffffffffffffffff80911690817fffffffffffffffffffffffff000000000000000000000000000000000000000060015416176001558254167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e227008380a380f35b5050346102ac57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac5760209073ffffffffffffffffffffffffffffffffffffffff600154169051908152f35b5080fd5b5090346104a05760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126104a0576102e9610b8f565b6024359073ffffffffffffffffffffffffffffffffffffffff9081831680930361049b57610315610c5e565b16908115610473578491908061036757508180809247905af1610336610bf5565b501561034157505080f35b517f90b8ec18000000000000000000000000000000000000000000000000000000008152fd5b928092505160208101917fa9059cbb00000000000000000000000000000000000000000000000000000000835260248201526044356044820152604481526080810181811067ffffffffffffffff821117610445578352516103da918691829182875af16103d3610bf5565b9084610caf565b8051908115159182610421575b50506103f35750505080f35b6024935051917f5274afe7000000000000000000000000000000000000000000000000000000008352820152fd5b819250906020918101031261019f576020015180159081150361019f5738806103e7565b6041867f4e487b71000000000000000000000000000000000000000000000000000000006000525260246000fd5b5050517f8579befe000000000000000000000000000000000000000000000000000000008152fd5b600080fd5b8280fd5b509190346102ac5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac576104de610b8f565b906104e7610c5e565b73ffffffffffffffffffffffffffffffffffffffff809216918215610576579383947f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da0321692833b1561019f576024859283855196879485937fc23a5cea0000000000000000000000000000000000000000000000000000000085528401525af190811561019657506101835750f35b8482517f8579befe000000000000000000000000000000000000000000000000000000008152fd5b808484346101a857827ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101a8576105d7610c5e565b73ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da03216803b156101a35783918351809581937fbb9fe6bf0000000000000000000000000000000000000000000000000000000083525af19081156101965750610652575080f35b61065b90610bb2565b80f35b5050346102ac57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac576020905173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032168152f35b5050346102ac57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac5773ffffffffffffffffffffffffffffffffffffffff60209254169051908152f35b5050346102ac57807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac579060209161075a610b8f565b9073ffffffffffffffffffffffffffffffffffffffff918352602435845280832081517fcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f36060527f5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e207683526160098652837f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c716601e5268603d3d8160223d3973600a52605f6021209083528460605260ff85536035523060601b60015260155260558320926035525191168152f35b5090346104a057827ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126104a0576001549173ffffffffffffffffffffffffffffffffffffffff9133838516036108d85750507fffffffffffffffffffffffff0000000000000000000000000000000000000000809216600155825491339083161783553391167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08380a380f35b6024925051907f118cdaa70000000000000000000000000000000000000000000000000000000082523390820152fd5b50913461019357807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101935750610941610c5e565b517f4a7f394f000000000000000000000000000000000000000000000000000000008152fd5b5090346104a057807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126104a05761099f610b8f565b73ffffffffffffffffffffffffffffffffffffffff928185526024356020528285209385928451937fcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f36060527f5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e20768652616009602052827f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c716601e5268603d3d8160223d3973600a52605f96602197605f60212060358801523060581b875260ff87538160158801526055872098893b15610b015750505050816001965b85875288606052169515610a95575b6020868651908152f35b853b15610afd577fc4d66de80000000000000000000000000000000000000000000000000000000084521690820152838160248183875af18015610af35760209450610ae4575b808080610a8b565b610aed90610bb2565b38610adc565b82513d86823e3d90fd5b8680fd5b909192985089f58015610b15578290610a7c565b8363301164258952601cfd5b8490346102ac57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ac5760209073ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c7168152f35b6004359073ffffffffffffffffffffffffffffffffffffffff8216820361049b57565b67ffffffffffffffff8111610bc657604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b3d15610c595767ffffffffffffffff903d828111610bc65760405192601f82017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0908116603f0116840190811184821017610bc65760405282523d6000602084013e565b606090565b73ffffffffffffffffffffffffffffffffffffffff600054163303610c7f57565b60246040517f118cdaa7000000000000000000000000000000000000000000000000000000008152336004820152fd5b90610cee5750805115610cc457805190602001fd5b60046040517f1425ea42000000000000000000000000000000000000000000000000000000008152fd5b81511580610d46575b610cff575090565b60249073ffffffffffffffffffffffffffffffffffffffff604051917f9996b315000000000000000000000000000000000000000000000000000000008352166004820152fd5b50803b15610cf756fea264697066735822122020672d0c03264e2785eb3a17a40742d95e9887bed833176dd597224a3829b8d664736f6c63430008170033";

    address internal constant _LIGHT_ACCOUNT = 0x8E8e658E22B12ada97B402fF0b044D6A325013C7;

    bytes internal constant _LIGHT_ACCOUNT_BYTECODE =
        hex"6080604081815260049081361015610022575b505050361561002057600080fd5b005b600092833560e01c90816301ffc9a714611307575080630a1028c414611294578063150b7a02146112065780631626ba7e1461117f57806318dfb3c7146110a857806319822f7c14610f5f57806347e1da2a14610e3b5780634a58db1914610d845780634d44560d14610c6a5780634f1ef28614610b1f57806352d1902d14610a9357806384b0196e146109615780638da5cb5b146108ef578063b0d691fe14610880578063b61d27f614610801578063bc197c8114610740578063c399ec881461068f578063c4d66de8146103f3578063d087d288146102f2578063f23a6e61146102615763f2fde38b03610012573461025d5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d57610149611506565b916101526119b0565b73ffffffffffffffffffffffffffffffffffffffff8093169283158015610254575b610225577f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200918254918216938486146101f65750507fffffffffffffffffffffffff000000000000000000000000000000000000000016831790557f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08380a380f35b908560249251917fb20f76e3000000000000000000000000000000000000000000000000000000008352820152fd5b508260249251917fb20f76e3000000000000000000000000000000000000000000000000000000008352820152fd5b50308414610174565b8280fd5b5082346102ef5760a07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef5761029a611506565b506102a3611529565b506084359067ffffffffffffffff82116102ef57506020926102c79136910161154c565b5050517ff23a6e61000000000000000000000000000000000000000000000000000000008152f35b80fd5b508290346103ef57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef578051927f35567e1a000000000000000000000000000000000000000000000000000000008452309084015281602484015260208360448173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032165afa9182156103e457916103aa575b6020925051908152f35b90506020823d6020116103dc575b816103c560209383611454565b810103126103d75760209151906103a0565b600080fd5b3d91506103b8565b9051903d90823e3d90fd5b5080fd5b50903461025d5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d5761042c611506565b917f33e4b41198cc5b8053630ed667ea7c0c4c873f7fc8d9a478b5d7259cec0a4a009182549160ff83821c16159267ffffffffffffffff811680159081610687575b600114908161067d575b159081610674575b5061064d578360017fffffffffffffffffffffffffffffffffffffffffffffffff00000000000000008316178655610618575b5073ffffffffffffffffffffffffffffffffffffffff8095169182156105ea575081907f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200827fffffffffffffffffffffffff000000000000000000000000000000000000000082541617905551947f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032167fec6a23b49d2c363d250c9dda15610e835d428207d15ddb36a6c230e37371ddf18780a3847f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08180a3610594578280f35b7fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d291817fffffffffffffffffffffffffffffffffffffffffffffff00ffffffffffffffff6020935416905560018152a138808280f35b8660249251917fb20f76e3000000000000000000000000000000000000000000000000000000008352820152fd5b7fffffffffffffffffffffffffffffffffffffffffffffff0000000000000000001668010000000000000001178455386104b3565b50517ff92ee8a9000000000000000000000000000000000000000000000000000000008152fd5b90501538610480565b303b159150610478565b85915061046e565b508290346103ef57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef578051927f70a08231000000000000000000000000000000000000000000000000000000008452309084015260208360248173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032165afa9182156103e457916103aa576020925051908152f35b5082346102ef5760a07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef57610779611506565b50610782611529565b5067ffffffffffffffff906044358281116103ef576107a4903690860161157a565b50506064358281116103ef576107bd903690860161157a565b50506084359182116102ef57506020926107d99136910161154c565b5050517fbc197c81000000000000000000000000000000000000000000000000000000008152f35b5050346103ef5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef5761083a611506565b6044359167ffffffffffffffff831161087c5761086061086f916108799436910161154c565b6108686119b0565b36916114cf565b9060243590611a98565b80f35b8380fd5b8382346103ef57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef576020905173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032168152f35b8382346103ef57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef5760209073ffffffffffffffffffffffffffffffffffffffff7f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be51220054169051908152f35b5082346102ef57807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef579080519061099e82611438565b600c82526020927f4c696768744163636f756e74000000000000000000000000000000000000000084840152610a4b8251926109d984611438565b600193600181527f320000000000000000000000000000000000000000000000000000000000000087820152610a3e8251967f0f00000000000000000000000000000000000000000000000000000000000000885260e08989015260e08801906115ab565b91868303908701526115ab565b4660608501523060808501528160a085015283810360c0850152846060519182815201946080925b828110610a805785870386f35b8351875295810195928101928401610a73565b5082346102ef57807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef57307f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c703610b1357602082517f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc8152f35b639f03a026915052601cfd5b5090817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d57610b52611506565b9160243567ffffffffffffffff8111610c6657610b72903690840161154c565b919093307f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c714610c5a5773ffffffffffffffffffffffffffffffffffffffff90610bba6119b0565b16926352d1902d6001527f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc90816020600183601d895afa5103610c4e575090828480949388967fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b8880a255610c2d578380f35b8190519485378338925af415610c4557818180808380f35b903d90823e3d90fd5b6355299b49600152601dfd5b83639f03a0268752601cfd5b8480fd5b508290346103ef57807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126103ef5782359073ffffffffffffffffffffffffffffffffffffffff80831680930361087c57610cc56119b0565b8215610d5c579383947f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da0321692833b15610c66576044859283855196879485937f205c287800000000000000000000000000000000000000000000000000000000855284015260243560248401525af1908115610d535750610d435750f35b610d4c906113f5565b6102ef5780f35b513d84823e3d90fd5b8482517f8579befe000000000000000000000000000000000000000000000000000000008152fd5b50827ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d578273ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da0321692833b156103ef5760248351809581937fb760faf9000000000000000000000000000000000000000000000000000000008352309083015234905af1908115610d535750610e32575080f35b610879906113f5565b503461025d5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d5767ffffffffffffffff908235828111610c6657610e8b903690850161157a565b602494919435848111610f5b57610ea5903690840161157a565b919094604435908111610f5757610ebf903690850161157a565b939094610eca6119b0565b848314801590610f4d575b610f27575050865b818110610ee8578780f35b80610f21610f01610efc600194868c6117eb565b61182a565b610f0c83878b6117eb565b35610f1b610868858a8c61189c565b91611a98565b01610edd565b517fa24a13a6000000000000000000000000000000000000000000000000000000008152fd5b5083831415610ed5565b8780fd5b8680fd5b508290346103ef577ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc916060833601126102ef5783359267ffffffffffffffff84116103ef576101209084360301126102ef576044359273ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da03216330361104b57602094611004916024359101611ac0565b9280611013575b505051908152f35b81808092337ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff150611043611a68565b50838061100b565b60648560208551917f08c379a0000000000000000000000000000000000000000000000000000000008352820152601c60248201527f6163636f756e743a206e6f742066726f6d20456e747279506f696e74000000006044820152fd5b50903461025d57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d5767ffffffffffffffff908035828111610c66576110f8903690830161157a565b909260243590811161117b57611111903690840161157a565b92909461111c6119b0565b838303610f27575050845b818110611132578580f35b611140610efc8284876117eb565b868061115061086885888b61189c565b602093828583519301915af190611165611a68565b9115611175575050600101611127565b81519101fd5b8580fd5b5082346102ef57817ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef576024359067ffffffffffffffff82116102ef57506111fe6020936111f77fffffffff00000000000000000000000000000000000000000000000000000000933690830161154c565b913561177b565b915191168152f35b5082346102ef5760807ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef5761123f611506565b50611248611529565b506064359067ffffffffffffffff82116102ef575060209261126c9136910161154c565b5050517f150b7a02000000000000000000000000000000000000000000000000000000008152f35b5082346102ef5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126102ef5782359067ffffffffffffffff82116102ef57366023830112156102ef57506112fb602093826024611300943693013591016114cf565b611609565b9051908152f35b8490843461025d5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261025d57357fffffffff00000000000000000000000000000000000000000000000000000000811680910361025d57602092507f150b7a020000000000000000000000000000000000000000000000000000000081149081156113cb575b81156113a1575b5015158152f35b7f01ffc9a7000000000000000000000000000000000000000000000000000000009150148361139a565b7f4e2312e00000000000000000000000000000000000000000000000000000000081149150611393565b67ffffffffffffffff811161140957604052565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b6040810190811067ffffffffffffffff82111761140957604052565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff82111761140957604052565b67ffffffffffffffff811161140957601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01660200190565b9291926114db82611495565b916114e96040519384611454565b8294818452818301116103d7578281602093846000960137010152565b6004359073ffffffffffffffffffffffffffffffffffffffff821682036103d757565b6024359073ffffffffffffffffffffffffffffffffffffffff821682036103d757565b9181601f840112156103d75782359167ffffffffffffffff83116103d757602083818601950101116103d757565b9181601f840112156103d75782359167ffffffffffffffff83116103d7576020808501948460051b0101116103d757565b919082519283825260005b8481106115f55750507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8460006020809697860101520116010190565b6020818301810151848301820152016115b6565b6020815191012060405160208101917f5e3baca2936049843f06038876a12f03627b5edc98025751ecf2ac75626401998352604082015260408152606081019181831067ffffffffffffffff841117611409578260405281519020917f4d0676c6b2436015d341483704315a5cf4b727092a2d2cb9a8a5f4ae2095b9bb917f0000000000000000000000008e8e658e22b12ada97b402ff0b044d6a325013c730147f0000000000000000000000000000000000000000000000000000000000000001461416156116f5575b5050671901000000000000600052601a52603a5260426018206000603a5290565b60a092507f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f82527fcbe29a6ace531c23849b5cdb1a6b991866eb7dc20deda15202ba6fd921ed2c0060808201527fad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5838201524660c082015260e0309101522038806116d4565b9061179a61179f9392604051906020820152602081526112fb81611438565b6118b7565b6117c7577fffffffff0000000000000000000000000000000000000000000000000000000090565b7f1626ba7e0000000000000000000000000000000000000000000000000000000090565b91908110156117fb5760051b0190565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b3573ffffffffffffffffffffffffffffffffffffffff811681036103d75790565b9035907fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe1813603018212156103d7570180359067ffffffffffffffff82116103d7576020019181360383136103d757565b908210156117fb576118b39160051b81019061184b565b9091565b90916001908181106119865780156117fb5781843560f81c80611917575081106103d7576119149361190e927fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff36930191016114cf565b90611cf2565b90565b146119465760046040517f60cd402d000000000000000000000000000000000000000000000000000000008152fd5b8082116103d75761191493611980927fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff36930191016114cf565b90611bfb565b60046040517f60cd402d000000000000000000000000000000000000000000000000000000008152fd5b73ffffffffffffffffffffffffffffffffffffffff807f0000000000000000000000000000000071727de22e5e9d8baf0edac6f37da032163314159081611a5d575b81611a2f575b506119ff57565b60246040517f4a0bfec1000000000000000000000000000000000000000000000000000000008152336004820152fd5b90507f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be5122005416331415386119f8565b3330141591506119f2565b3d15611a93573d90611a7982611495565b91611a876040519384611454565b82523d6000602084013e565b606090565b916000928392602083519301915af1611aaf611a68565b9015611ab85750565b602081519101fd5b610100810190611ad0828261184b565b929050600180931061198657611ae6818361184b565b156117fb573560f81c80611b775750611b2c906000947f19457468657265756d205369676e6564204d6573736167653a0a3332000000008652601c52603c85209261184b565b90818411610c6657611b69929161190e91857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff36930191016114cf565b15611b72575090565b905090565b9280949314611baa5760046040517f60cd402d000000000000000000000000000000000000000000000000000000008152fd5b611bb39161184b565b91908284116103d757611bf09261198091857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff36930191016114cf565b156119145750600090565b906000809173ffffffffffffffffffffffffffffffffffffffff7f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200541690604051611caf81611c8360208201947f1626ba7e00000000000000000000000000000000000000000000000000000000998a875260248401526040604484015260648301906115ab565b037fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe08101835282611454565b51915afa90611cbc611a68565b82611ce4575b82611ccc57505090565b9091506020818051810103126103d757602001511490565b915060208251101591611cc2565b611d0891611cff91611d47565b90929192611d83565b73ffffffffffffffffffffffffffffffffffffffff807f691ec1a18226d004c07c9f8e5c4a6ff15a7b38db267cf7e3c945aef8be512200541691161490565b8151919060418303611d7857611d7192506020820151906060604084015193015160001a90611e6a565b9192909190565b505060009160029190565b6004811015611e3b5780611d95575050565b60018103611dc75760046040517ff645eedf000000000000000000000000000000000000000000000000000000008152fd5b60028103611e0057602482604051907ffce698f70000000000000000000000000000000000000000000000000000000082526004820152fd5b600314611e0a5750565b602490604051907fd78bce0c0000000000000000000000000000000000000000000000000000000082526004820152fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411611efb57926020929160ff608095604051948552168484015260408301526060820152600092839182805260015afa15611eef57805173ffffffffffffffffffffffffffffffffffffffff811615611ee657918190565b50809160019190565b604051903d90823e3d90fd5b5050506000916003919056fea26469706673582212200896f337e411e9db94675cb703bb4056435327d18f202a547674e38ca452f52464736f6c63430008170033";

    ILightAccountFactory internal _factory = ILightAccountFactory(payable(_LIGHT_ACCOUNT_FACTORY));

    function setUp() public {
        vm.etch(_LIGHT_ACCOUNT_FACTORY, _LIGHT_ACCOUNT_FACTORY_BYTECODE);
        vm.etch(_LIGHT_ACCOUNT, _LIGHT_ACCOUNT_BYTECODE);
    }

    function test_lightAccountGas_runtime_accountCreation() public {
        uint256 gasUsed =
            _runtimeBenchmark(owner1, address(_factory), abi.encodeCall(_factory.createAccount, (owner1, 0)));

        assertTrue(_factory.getAddress(owner1, 0).code.length > 0);

        _snap(RUNTIME, "AccountCreation", gasUsed);
    }

    function test_lightAccountGas_runtime_nativeTransfer() public {
        ILightAccount account = ILightAccount(payable(_factory.createAccount(owner1, 0)));

        vm.deal(address(account), 1 ether);

        uint256 gasUsed = _runtimeBenchmark(
            owner1, address(account), abi.encodeCall(account.execute, (recipient, 0.1 ether, ""))
        );

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(RUNTIME, "NativeTransfer", gasUsed);
    }

    function test_lightAccountGas_userOp_nativeTransfer() public {
        ILightAccount account1 = ILightAccount(payable(_factory.createAccount(owner1, 0)));

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(ILightAccount.execute, (recipient, 0.1 ether, "")),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 80_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));
        // uint8(0) is LightAccount.SignatureType.EOA. For some reason, the enum does not appear in the ABI.
        userOp.signature = abi.encodePacked(uint8(0), r, s, v);

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(address(recipient).balance, 0.1 ether + 1 wei);

        _snap(USER_OP, "NativeTransfer", gasUsed);
    }

    function test_lightAccountGas_runtime_erc20Transfer() public {
        ILightAccount account = ILightAccount(payable(_factory.createAccount(owner1, 0)));

        mockErc20.mint(address(account), 100 ether);

        uint256 gasUsed = _runtimeBenchmark(
            owner1,
            address(account),
            abi.encodeCall(
                account.execute, (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
            )
        );

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(RUNTIME, "Erc20Transfer", gasUsed);
    }

    function test_lightAccountGas_userOp_erc20Transfer() public {
        ILightAccount account1 = ILightAccount(payable(_factory.createAccount(owner1, 0)));

        mockErc20.mint(address(account1), 100 ether);

        vm.deal(address(account1), 1 ether);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account1),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(
                ILightAccount.execute,
                (address(mockErc20), 0, abi.encodeCall(mockErc20.transfer, (recipient, 10 ether)))
            ),
            // don't over-estimate by a lot here, otherwise a fee is assessed.
            accountGasLimits: _encodeGasLimits(40_000, 80_000),
            preVerificationGas: 0,
            gasFees: _encodeGasFees(1, 1),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner1Key, MessageHashUtils.toEthSignedMessageHash(userOpHash));

        userOp.signature = abi.encodePacked(uint8(0), r, s, v);

        uint256 gasUsed = _userOpBenchmark(userOp);

        assertEq(mockErc20.balanceOf(recipient), 10 ether);

        _snap(USER_OP, "Erc20Transfer", gasUsed);
    }
}
