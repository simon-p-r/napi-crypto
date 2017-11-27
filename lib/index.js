'use strict';

const Native = require('bindings')('napi-crypto');

module.exports = {

    createKeyPair: Native.createKeyPair,
    createKeyPairAsync: () => {

        return new Promise((resolve, reject) => {

            Native.createKeyPairAsync((err, keys) => {

                // $lab:coverage:off$
                if (err) {
                    reject(err);
                }
                // $lab:coverage:on$
                resolve(keys);
            });
        });
    },
    createCSR: Native.createCSR,
    getFingerprint: Native.getFingerprint
};
