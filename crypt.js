const bcrypt = require('bcryptjs')

const hash = async (message = '') => {
    const myHash = await bcrypt.hash(message, 10)
    console.log('myHash', myHash)
    return myHash
}

hash('probando')